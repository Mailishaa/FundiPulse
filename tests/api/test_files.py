"""End-to-end tests for file upload, metadata and authorised download.

The point of this module is not that a file can be uploaded. It is that every
attempt to reach someone else's bytes fails, that a lying client cannot talk the
server into storing the wrong thing, and that an object which has not been
scanned never becomes downloadable - because the storage layer would happily
sign it.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
import io
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import func, select
from starlette.datastructures import Headers, UploadFile

from app.api.routes.files import router as files_router
from app.core.config import Settings, get_settings
from app.core.constants import (
    AuditAction,
    EvidenceVisibility,
    ProfileVisibility,
    ScanStatus,
    UserRole,
)
from app.core.exceptions import (
    FileNotScannedError,
    FileTooLargeError,
    NotFoundError,
    ValidationError,
)
from app.core.storage import InMemoryStorage, StorageError, get_storage, reset_storage
from app.db.models.file import FileObject
from app.db.models.user import User
from app.db.models.worker import Credential, EvidenceItem, Project, WorkerProfile
from app.db.session import get_db
from app.schemas.files import FileUploadRequest
from app.services.auth_service import RequestContext
from app.services.file_service import (
    FileService,
    clamp_evidence_visibility,
    read_upload_stream,
    resolve_scan_policy,
)
from app.utils.fileinspect import content_disposition_value

pytestmark = [pytest.mark.api, pytest.mark.integration]

# --------------------------------------------------------------------------- #
# Payloads. Only the leading bytes matter: sniffing reads a magic number, and a
# real encoder is not what is under test here.                               #
# --------------------------------------------------------------------------- #
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 48
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 48
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"trailer\n%%EOF\n" + b"\x00" * 32
SCRIPT = b"#!/bin/sh\nrm -rf /\n" + b"\x00" * 32
PE_BINARY = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 48

#: Bidi override (U+202E). Renders as a left-to-right run, so ``photo<RLO>gnp.png``
#: displays as ``photognp.png`` - a filename that lies about its own extension.
RLO = "\u202e"

BOUNDARY = "----fundipulse-files-test"


def multipart_body(filename: str, data: bytes, *, content_type: str = "image/png") -> bytes:
    """Hand-build a one-part multipart body.

    Needed because a client library will not put a NUL byte in a filename, and
    because lying about ``Content-Length`` is the whole point of two of these
    tests.
    """
    head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    )
    # utf-8, not latin-1: one of these filenames is deliberately not latin-1
    # encodable, which is precisely how a bidi override reaches a server.
    return head.encode("utf-8") + data + f"\r\n--{BOUNDARY}--\r\n".encode()


MULTIPART_HEADERS = {"content-type": f"multipart/form-data; boundary={BOUNDARY}"}


class CountingStream(io.BytesIO):
    """A stream that remembers how many bytes were pulled out of it."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = super().read(size)
        self.bytes_read += len(chunk)
        return chunk


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
class RecordingStorage(InMemoryStorage):
    """An in-memory backend that remembers what it was asked to sign.

    Lets a test assert that signing was *not* attempted for a file that must not
    be released, which is the property the whole download route exists to hold.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.put_keys: list[str] = []
        self.download_calls: list[dict] = []

    def put_object(self, *, object_key: str, data: bytes, content_type: str, metadata=None):
        self.put_keys.append(object_key)
        return super().put_object(
            object_key=object_key, data=data, content_type=content_type, metadata=metadata
        )

    def create_download_url(self, **kwargs) -> str:
        self.download_calls.append(kwargs)
        return super().create_download_url(**kwargs)


@pytest.fixture(autouse=True)
def storage() -> Iterator[InMemoryStorage]:
    """A private in-memory backend per test, so nothing leaks between them."""
    reset_storage()
    yield get_storage()
    reset_storage()


def _includes_router(routes, target) -> bool:
    """Whether ``target`` appears anywhere in a (possibly nested) route tree.

    FastAPI keeps included routers as wrapper objects rather than flattening
    them, so this walks the tree rather than looking at one level.
    """
    for route in routes:
        if getattr(route, "original_router", None) is target:
            return True
        nested = getattr(route, "routes", None)
        if nested and _includes_router(nested, target):
            return True
    return False


@pytest.fixture
def files_app(app):
    """Guarantee the files router is mounted on the application under test.

    ``app/api/router.py`` is owned by another agent, so this module does not
    assume the mount has happened - it only adds it when it is missing. Either
    way the tests exercise the real router object, dependency wiring and error
    envelope.
    """
    if not _includes_router(app.router.routes, files_router):
        app.include_router(files_router)
    return app


@pytest.fixture
def client(files_app, db_session) -> Iterator[TestClient]:
    """A client over an app that definitely has the files router mounted.

    Mirrors the shared ``client`` fixture's ``get_db`` override, so fixtures and
    HTTP calls share one transaction.
    """

    def _override_get_db() -> Iterator:
        yield db_session
        db_session.flush()

    files_app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(files_app, raise_server_exceptions=False) as test_client:
            yield test_client
    finally:
        files_app.dependency_overrides.clear()


@pytest.fixture
def worker(make_user, auth_headers) -> dict:
    user = make_user()
    return {"user": user, "headers": auth_headers(user)}


@pytest.fixture
def make_passport(db_session):
    """Create a Work Passport for any user, defaulting to ``PRIVATE``."""

    def _factory(user: User, *, visibility: ProfileVisibility = ProfileVisibility.PRIVATE):
        profile = WorkerProfile(
            user_id=user.id,
            display_name="Amina Wanjiru",
            visibility=visibility.value,
        )
        db_session.add(profile)
        db_session.flush()
        return profile

    return _factory


@pytest.fixture
def passport(db_session, worker, make_passport) -> WorkerProfile:
    profile = make_passport(worker["user"])
    worker["profile"] = profile
    return profile


@pytest.fixture
def small_upload_ceiling(monkeypatch) -> Iterator[int]:
    """Shrink the upload ceiling so an oversized payload is cheap to build."""
    monkeypatch.setenv("MAX_UPLOAD_SIZE_BYTES", "1024")
    get_settings.cache_clear()
    reset_storage()
    yield 1024
    get_settings.cache_clear()
    reset_storage()


@pytest.fixture
def project(db_session, passport) -> Project:
    record = Project(
        worker_profile_id=passport.id,
        name="River House block C",
        role_title="Mason",
    )
    db_session.add(record)
    db_session.flush()
    return record


def upload_bytes(
    client: TestClient,
    headers: dict,
    *,
    data: bytes = PNG,
    filename: str = "site-photo.png",
    content_type: str = "image/png",
    fields: dict | None = None,
):
    """POST an upload with the given multipart part."""
    return client.post(
        "/files/upload",
        headers=headers,
        files={"file": (filename, data, content_type)},
        data=fields or {},
    )


def upload_record(db_session, owner: User) -> FileObject | None:
    return db_session.execute(
        select(FileObject).where(FileObject.owner_user_id == owner.id)
    ).scalar_one_or_none()


def service(db_session, **kwargs) -> FileService:
    return FileService(db_session, **kwargs)


def upload_request(
    data: bytes,
    *,
    filename: str | None = "site-photo.png",
    content_type: str | None = "image/png",
    size: int | None = None,
    **kwargs,
) -> FileUploadRequest:
    """Build the same request object FastAPI would build, for service-level tests."""
    stream = io.BytesIO(data)
    return FileUploadRequest(
        file=UploadFile(
            stream,
            size=len(data) if size is None else size,
            filename=filename,
            headers=Headers({"content-type": content_type} if content_type else {}),
        ),
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Upload: happy path                                                          #
# --------------------------------------------------------------------------- #
class TestUpload:
    def test_stores_the_bytes_and_returns_sniffed_metadata(
        self, client, worker, db_session, storage
    ):
        response = upload_bytes(client, worker["headers"])

        assert response.status_code == 201, response.text
        data = response.json()["data"]["file"]
        assert data["content_type"] == "image/png"
        assert data["original_filename"] == "site-photo.png"
        assert data["size_bytes"] == len(PNG)
        assert data["purpose"] == "WORK_EVIDENCE"

        record = upload_record(db_session, worker["user"])
        assert record is not None
        assert record.sha256 == data["sha256"]
        assert record.bucket == storage.bucket

    def test_object_key_is_generated_and_contains_no_user_input(self, client, worker, db_session):
        upload_bytes(client, worker["headers"], filename="../../etc/passwd.png")

        record = upload_record(db_session, worker["user"])
        assert record is not None
        prefix, owner, token_and_ext = record.object_key.split("/")
        assert prefix == "WORK_EVIDENCE"
        assert owner == str(worker["user"].id)
        assert token_and_ext.endswith(".png")
        assert ".." not in record.object_key
        assert "passwd" not in record.object_key

    def test_a_new_upload_is_pending_and_quarantined(self, client, worker):
        """Nothing is clean because it was checked; it is clean because it was not."""
        data = upload_bytes(client, worker["headers"]).json()["data"]["file"]

        assert data["scan_status"] == ScanStatus.PENDING.value
        assert data["is_quarantined"] is True
        assert data["is_downloadable"] is False

    def test_scan_policy_is_pending_whichever_way_the_flag_is_set(self):
        """Turning the scanner on must not be what makes a file safe."""
        for enabled in (False, True):
            policy = resolve_scan_policy(
                get_settings().model_copy(update={"malware_scanning_enabled": enabled})
            )
            assert policy.scanning_enabled is enabled
            assert policy.scan_status is ScanStatus.PENDING
            assert policy.is_quarantined is True

    @pytest.mark.parametrize(
        ("data", "filename", "content_type", "expected"),
        [
            (JPEG, "photo.jpg", "image/jpeg", "image/jpeg"),
            (PNG, "photo.png", "image/png", "image/png"),
            (PDF, "contract.pdf", "application/pdf", "application/pdf"),
        ],
    )
    def test_each_supported_format_is_stored_under_its_sniffed_type(
        self, client, worker, data, filename, content_type, expected
    ):
        response = upload_bytes(
            client, worker["headers"], data=data, filename=filename, content_type=content_type
        )

        assert response.status_code == 201, response.text
        assert response.json()["data"]["file"]["content_type"] == expected

    def test_metadata_never_exposes_the_storage_location(self, client, worker, db_session):
        """No object key, no bucket: a leaked key is a leaked file."""
        upload_bytes(client, worker["headers"])

        record = upload_record(db_session, worker["user"])
        metadata = client.get(f"/files/{record.id}", headers=worker["headers"])

        assert metadata.status_code == 200, metadata.text
        assert record.object_key not in metadata.text
        assert record.bucket not in metadata.text
        assert "object_key" not in metadata.json()["data"]
        assert "bucket" not in metadata.json()["data"]

    def test_upload_is_audited_as_a_security_event(self, client, worker, db_session, audit_rows):
        record_id = upload_bytes(client, worker["headers"]).json()["data"]["file"]["id"]

        rows = audit_rows(action=AuditAction.FILE_UPLOADED, resource_id=record_id)

        assert len(rows) == 1
        assert rows[0].resource_type == "file"
        assert rows[0].outcome == "SUCCESS"
        assert rows[0].actor_user_id == worker["user"].id

    def test_audit_row_records_no_filename_or_content(self, client, worker, audit_rows):
        upload_bytes(client, worker["headers"], filename="national-id-scan.png")

        row = audit_rows(action=AuditAction.FILE_UPLOADED)[0]

        assert "national-id-scan" not in str(row.metadata_)
        assert row.metadata_["scan_status"] == ScanStatus.PENDING.value

    @pytest.mark.parametrize("field", [{"owner_user_id": "x"}, {"is_quarantined": "false"}])
    def test_mass_assignment_attempts_are_refused(self, client, worker, error_code, field):
        response = upload_bytes(client, worker["headers"], fields=field)

        assert response.status_code == 422
        assert error_code(response) == "VALIDATION_FAILED"


# --------------------------------------------------------------------------- #
# Upload: refusals                                                            #
# --------------------------------------------------------------------------- #
class TestUploadRefusals:
    def test_oversized_is_rejected(self, client, worker, error_code):
        """413 either way: the request cap or the per-file cap gets there first."""
        response = upload_bytes(client, worker["headers"], data=PNG + b"\x00" * (300 * 1024))

        assert response.status_code == 413
        assert error_code(response) in {"PAYLOAD_TOO_LARGE", "FILE_TOO_LARGE"}

    def test_wrong_extension_is_rejected(self, client, worker, error_code):
        """PNG bytes named ``.txt``: the extension allowlist has no ``.txt``."""
        response = upload_bytes(client, worker["headers"], filename="notes.txt")

        assert response.status_code == 415
        assert error_code(response) == "UNSUPPORTED_FILE_TYPE"

    @pytest.mark.parametrize(
        ("filename", "data", "content_type"),
        [
            ("installer.exe", PE_BINARY, "application/x-msdownload"),
            ("run.sh", SCRIPT, "application/x-sh"),
        ],
    )
    def test_executable_content_is_rejected(
        self, client, worker, error_code, filename, data, content_type
    ):
        response = upload_bytes(
            client, worker["headers"], filename=filename, data=data, content_type=content_type
        )

        assert response.status_code == 415
        assert error_code(response) == "UNSUPPORTED_FILE_TYPE"

    def test_mime_spoofing_a_jpeg_that_is_a_script_is_rejected(self, client, worker, error_code):
        """The declared type and the extension both say JPEG; the bytes say shell."""
        response = upload_bytes(
            client,
            worker["headers"],
            data=SCRIPT,
            filename="vacancy.jpg",
            content_type="image/jpeg",
        )

        assert response.status_code == 415
        assert error_code(response) == "UNSUPPORTED_FILE_TYPE"
        assert "script" not in response.text.lower()

    def test_bytes_that_contradict_the_declared_type_are_rejected(self, client, worker, error_code):
        response = upload_bytes(
            client, worker["headers"], data=PDF, filename="photo.jpg", content_type="image/jpeg"
        )

        assert response.status_code == 415
        assert error_code(response) == "UNSUPPORTED_FILE_TYPE"

    def test_bytes_that_contradict_the_extension_are_rejected(self, client, worker, error_code):
        response = upload_bytes(client, worker["headers"], data=PDF, filename="photo.png")

        assert response.status_code == 415
        assert error_code(response) == "UNSUPPORTED_FILE_TYPE"

    def test_empty_upload_is_rejected(self, client, worker, error_code):
        response = upload_bytes(client, worker["headers"], data=b"")

        assert response.status_code in {422, 415}
        assert error_code(response) in {"VALIDATION_FAILED", "UNSUPPORTED_FILE_TYPE"}

    def test_a_purpose_owned_by_another_domain_is_refused(self, client, worker, error_code):
        response = upload_bytes(client, worker["headers"], fields={"purpose": "ORGANIZATION_LOGO"})

        assert response.status_code == 422
        assert error_code(response) == "VALIDATION_FAILED"

    def test_a_refused_upload_is_audited(self, client, worker, audit_rows):
        upload_bytes(client, worker["headers"], data=SCRIPT, filename="x.jpg")

        rows = audit_rows(action=AuditAction.FILE_ACCESS_DENIED)

        assert len(rows) == 1
        assert rows[0].outcome == "DENIED"
        assert rows[0].metadata_["operation"] == "upload"
        assert rows[0].metadata_["reason"] == "UNSUPPORTED_FILE_TYPE"


# --------------------------------------------------------------------------- #
# Upload: filename hardening                                                  #
# --------------------------------------------------------------------------- #
class TestFilenames:
    def test_path_traversal_filename_becomes_display_metadata_only(
        self, client, worker, db_session
    ):
        response = upload_bytes(client, worker["headers"], filename="../../etc/passwd")

        assert response.status_code == 201, response.text
        stored = response.json()["data"]["file"]["original_filename"]
        assert stored == "passwd"
        assert "/" not in stored
        assert "etc/passwd" not in response.text

        record = upload_record(db_session, worker["user"])
        assert ".." not in record.object_key

    def test_path_traversal_filename_with_an_allowed_extension(self, client, worker, db_session):
        response = upload_bytes(client, worker["headers"], filename="../../../var/www/a.png")

        assert response.status_code == 201, response.text
        stored = response.json()["data"]["file"]["original_filename"]
        assert stored == "a.png"
        assert ".." not in stored

        record = upload_record(db_session, worker["user"])
        assert stored not in record.object_key

    def test_null_byte_in_filename_is_stripped(self, client, worker, db_session):
        """A NUL truncates a C string. It must not survive into a header or a path."""
        body = multipart_body("ev\x00il.png", PNG)
        response = client.post(
            "/files/upload", headers={**worker["headers"], **MULTIPART_HEADERS}, content=body
        )

        assert response.status_code == 201, response.text
        stored = response.json()["data"]["file"]["original_filename"]
        assert "\x00" not in stored
        assert stored == "evil.png"

        record = upload_record(db_session, worker["user"])
        assert "\x00" not in record.object_key

    def test_bidi_override_in_filename_is_stripped(self, client, worker, db_session):
        """``photo<RLO>gnp.png`` renders as ``photoexe.png`` on a screen."""
        body = multipart_body(f"photo{RLO}gnp.png", PNG)
        response = client.post(
            "/files/upload", headers={**worker["headers"], **MULTIPART_HEADERS}, content=body
        )

        assert response.status_code == 201, response.text
        stored = response.json()["data"]["file"]["original_filename"]
        assert RLO not in stored
        assert stored == "photognp.png"

        record = upload_record(db_session, worker["user"])
        assert RLO not in record.object_key

    def test_a_plain_unicode_filename_is_kept_for_display(self, client, worker):
        body = multipart_body("übersicht-照片.png", PNG)
        response = client.post(
            "/files/upload", headers={**worker["headers"], **MULTIPART_HEADERS}, content=body
        )

        assert response.status_code == 201, response.text
        stored = response.json()["data"]["file"]["original_filename"]
        assert "übersicht" in stored
        assert "照片" in stored

    def test_a_filename_that_sanitises_to_nothing_falls_back(self, client, worker):
        body = multipart_body("....png", PNG)
        response = client.post(
            "/files/upload", headers={**worker["headers"], **MULTIPART_HEADERS}, content=body
        )

        assert response.status_code == 201, response.text
        assert response.json()["data"]["file"]["original_filename"] == "png"


# --------------------------------------------------------------------------- #
# Size enforcement, including a lying client                                 #
# --------------------------------------------------------------------------- #
class TestBoundedReading:
    def test_a_lying_content_length_is_caught_by_reading(
        self, client, worker, error_code, small_upload_ceiling
    ):
        """The declared length says 60 bytes. The ceiling is 1024. The bytes are 64 KiB.

        A service that trusted the header would read 60 bytes, find a valid PNG
        header and store a truncated file. The bounded loop is what makes this a
        413.
        """
        body = multipart_body("site-photo.png", PNG + b"\x00" * (64 * 1024))
        response = client.post(
            "/files/upload",
            headers={**worker["headers"], **MULTIPART_HEADERS, "content-length": "60"},
            content=body,
        )

        assert response.status_code == 413, response.text
        assert error_code(response) == "FILE_TOO_LARGE"

    def test_read_upload_stream_stops_reading_at_the_ceiling(self):
        """The refusal must be reached without buffering the whole stream."""
        stream = CountingStream(b"\x00" * 10_000)
        ceiling = 1024

        with pytest.raises(FileTooLargeError):
            read_upload_stream(stream, declared_size=64, max_bytes=ceiling)

        assert stream.bytes_read <= ceiling + 1

    def test_read_upload_stream_refuses_an_oversized_declared_length_without_reading(self):
        stream = CountingStream(b"\x00" * 10_000)

        with pytest.raises(FileTooLargeError):
            read_upload_stream(stream, declared_size=5000, max_bytes=1024)

        assert stream.bytes_read == 0

    def test_upload_of_an_oversized_stream_stores_nothing(self, db_session, worker):
        """A stream that lies about its size is refused before anything is stored."""
        recorder = RecordingStorage()
        tiny = Settings(app_env="test", max_upload_size_bytes=1024)
        oversized = upload_request(PNG + b"\x00" * 5000, size=100)

        with pytest.raises(FileTooLargeError):
            service(db_session, storage=recorder, settings=tiny).upload(
                actor=worker["user"], payload=oversized, ctx=RequestContext()
            )

        assert recorder.put_keys == []

    def test_a_configured_ceiling_below_the_hard_cap_is_enforced(self, db_session, worker):
        tiny = Settings(app_env="test", max_upload_size_bytes=1024)
        recorder = RecordingStorage()

        with pytest.raises(FileTooLargeError):
            service(db_session, storage=recorder, settings=tiny).upload(
                actor=worker["user"],
                payload=upload_request(PNG + b"\x00" * 4096),
                ctx=RequestContext(),
            )

        assert recorder.put_keys == []


# --------------------------------------------------------------------------- #
# Authorisation                                                               #
# --------------------------------------------------------------------------- #
class TestAuthorisation:
    def test_metadata_requires_authentication(self, client, db_session, worker, error_code):
        record_id = upload_bytes(client, worker["headers"]).json()["data"]["file"]["id"]

        response = client.get(f"/files/{record_id}")

        assert response.status_code == 401
        assert error_code(response) == "AUTHENTICATION_REQUIRED"

    def test_download_requires_authentication(self, client, worker, error_code):
        record_id = upload_bytes(client, worker["headers"]).json()["data"]["file"]["id"]

        response = client.get(f"/files/{record_id}/download")

        assert response.status_code == 401
        assert error_code(response) == "AUTHENTICATION_REQUIRED"

    def test_an_invalid_token_is_refused(self, client, worker, error_code):
        response = client.get(
            "/files/" + str(uuid.uuid4()), headers={"Authorization": "Bearer nope"}
        )

        assert response.status_code == 401
        assert error_code(response) == "INVALID_TOKEN"

    def test_a_bogus_file_id_is_a_404(self, client, worker, error_code):
        response = client.get(f"/files/{uuid.uuid4()}", headers=worker["headers"])

        assert response.status_code == 404
        assert error_code(response) == "RESOURCE_NOT_FOUND"

    def test_worker_b_cannot_read_worker_a_metadata(
        self, client, make_user, auth_headers, error_code
    ):
        """404, not 403: a 403 would confirm the file exists."""
        owner = make_user()
        record_id = upload_bytes(client, auth_headers(owner)).json()["data"]["file"]["id"]
        intruder = make_user()

        response = client.get(f"/files/{record_id}", headers=auth_headers(intruder))

        assert response.status_code == 404
        assert error_code(response) == "RESOURCE_NOT_FOUND"

    def test_worker_b_cannot_download_worker_a_file(
        self, client, make_user, auth_headers, error_code
    ):
        owner = make_user()
        record_id = upload_bytes(client, auth_headers(owner)).json()["data"]["file"]["id"]
        intruder = make_user()

        response = client.get(f"/files/{record_id}/download", headers=auth_headers(intruder))

        assert response.status_code == 404
        assert error_code(response) == "RESOURCE_NOT_FOUND"

    def test_an_employer_cannot_read_a_workers_private_evidence(
        self, client, db_session, make_user, auth_headers, error_code, make_passport
    ):
        owner = make_user()
        make_passport(owner)
        record_id = upload_bytes(
            client,
            auth_headers(owner),
            fields={"attach_as_evidence": "true", "visibility": "EMPLOYERS"},
        ).json()["data"]["file"]["id"]
        employer = make_user(role=UserRole.EMPLOYER)

        for path in (f"/files/{record_id}", f"/files/{record_id}/download"):
            response = client.get(path, headers=auth_headers(employer))
            assert response.status_code == 404, path
            assert error_code(response) == "RESOURCE_NOT_FOUND", path

        assert owner.id != employer.id

    def test_a_cross_user_read_is_audited(self, client, make_user, auth_headers, audit_rows):
        owner = make_user()
        record_id = upload_bytes(client, auth_headers(owner)).json()["data"]["file"]["id"]
        intruder = make_user()

        client.get(f"/files/{record_id}", headers=auth_headers(intruder))
        client.get(f"/files/{record_id}/download", headers=auth_headers(intruder))

        denied = audit_rows(action=AuditAction.FILE_ACCESS_DENIED)
        assert {row.metadata_["operation"] for row in denied} == {
            "read_metadata",
            "download_url",
        }
        assert all(row.actor_user_id == intruder.id for row in denied)

    def test_an_admin_is_not_an_implicit_bypass(
        self, client, make_admin, make_user, auth_headers, error_code
    ):
        """Private documents have no standing admin shortcut here.

        A moderation path that needs one has to be an explicit, separately audited
        action - not a consequence of the role column.
        """
        owner = make_user()
        record_id = upload_bytes(client, auth_headers(owner)).json()["data"]["file"]["id"]
        admin = make_admin()

        response = client.get(f"/files/{record_id}", headers=auth_headers(admin))

        assert response.status_code == 404
        assert error_code(response) == "RESOURCE_NOT_FOUND"

    def test_metadata_never_leaks_another_users_file_details(
        self, client, make_user, auth_headers, db_session
    ):
        """A 404 body, not a redaction of the real record."""
        owner = make_user()
        upload_bytes(client, auth_headers(owner))
        record = upload_record(db_session, owner)
        intruder = make_user()

        response = client.get(f"/files/{record.id}", headers=auth_headers(intruder))

        assert response.status_code == 404
        assert record.original_filename not in response.text
        assert record.sha256 not in response.text
        assert record.object_key not in response.text


# --------------------------------------------------------------------------- #
# Download                                                                    #
# --------------------------------------------------------------------------- #
class TestDownload:
    def _upload(self, client, worker):
        return upload_bytes(client, worker["headers"]).json()["data"]["file"]

    def test_an_unscanned_file_is_not_downloadable(self, client, worker, error_code):
        record_id = self._upload(client, worker)["id"]

        response = client.get(f"/files/{record_id}/download", headers=worker["headers"])

        assert response.status_code == 409
        assert error_code(response) == "FILE_NOT_SCANNED"

    def test_a_quarantined_file_is_not_downloadable(self, client, db_session, worker, error_code):
        self._upload(client, worker)
        record = upload_record(db_session, worker["user"])
        record.scan_status = ScanStatus.PENDING.value
        record.is_quarantined = True
        db_session.flush()

        response = client.get(f"/files/{record.id}/download", headers=worker["headers"])

        assert response.status_code == 409
        assert error_code(response) == "FILE_NOT_SCANNED"

    def test_an_infected_file_is_refused(self, client, db_session, worker, error_code):
        self._upload(client, worker)
        record = upload_record(db_session, worker["user"])
        record.scan_status = ScanStatus.INFECTED.value
        record.is_quarantined = True
        db_session.flush()

        response = client.get(f"/files/{record.id}/download", headers=worker["headers"])

        assert response.status_code == 409
        assert error_code(response) == "FILE_INFECTED"

    def test_a_clean_file_gets_a_short_lived_url(self, client, db_session, worker):
        """The only route to a URL is a scanner verdict, which nothing issues yet."""
        record_id = self._upload(client, worker)["id"]
        service(db_session).apply_scan_result(
            file_id=uuid.UUID(record_id),
            status=ScanStatus.CLEAN,
            engine="test-scanner",
            ctx=RequestContext(),
        )

        response = client.get(f"/files/{record_id}/download", headers=worker["headers"])

        assert response.status_code == 200, response.text
        data = response.json()["data"]
        ttl = get_settings().signed_url_ttl_seconds
        assert data["download_url"].startswith("memory://")
        assert data["expires_in_seconds"] == ttl
        assert data["download_filename"] == "site-photo.png"
        expiry = datetime.fromisoformat(data["expires_at"])
        assert expiry.tzinfo is not None
        assert expiry < datetime.now(UTC) + timedelta(seconds=ttl + 30)

    def test_issuing_a_url_counts_the_access_and_is_audited(
        self, client, db_session, worker, audit_rows
    ):
        record_id = self._upload(client, worker)["id"]
        service(db_session).apply_scan_result(
            file_id=uuid.UUID(record_id),
            status=ScanStatus.CLEAN,
            engine="test-scanner",
            ctx=RequestContext(),
        )

        client.get(f"/files/{record_id}/download", headers=worker["headers"])
        record = upload_record(db_session, worker["user"])

        assert record.access_count == 1
        assert record.last_accessed_at is not None
        rows = audit_rows(action=AuditAction.FILE_DOWNLOAD_URL_ISSUED, resource_id=record.id)
        assert len(rows) == 1

    def test_a_refused_download_is_audited(self, client, worker, audit_rows):
        record_id = self._upload(client, worker)["id"]

        client.get(f"/files/{record_id}/download", headers=worker["headers"])

        rows = audit_rows(action=AuditAction.FILE_ACCESS_DENIED)
        assert [row.metadata_["reason"] for row in rows] == ["FILE_NOT_SCANNED"]

    def test_signing_is_never_attempted_for_an_unscanned_object(self, client, db_session, worker):
        """The ordering is the control: authorise, then check, then sign.

        ``RecordingStorage`` would sign anything handed to it. The assertion is
        that it was never asked.
        """
        self._upload(client, worker)
        recorder = RecordingStorage()
        record = upload_record(db_session, worker["user"])

        with pytest.raises(FileNotScannedError):
            service(db_session, storage=recorder).issue_download_url(
                actor=worker["user"], file_id=record.id, ctx=RequestContext()
            )

        assert recorder.download_calls == []

    def test_the_disposition_value_is_escaped_not_the_raw_filename(
        self, client, db_session, worker
    ):
        """``create_download_url`` takes a complete, already-escaped header value.

        A bare filename is not a ``Content-Disposition`` value, and passing one
        would hand the stored name whatever header syntax it liked.
        """
        self._upload(client, worker)
        record = upload_record(db_session, worker["user"])
        record.original_filename = "photo\u00fc.png"
        db_session.flush()
        service(db_session).apply_scan_result(
            file_id=record.id,
            status=ScanStatus.CLEAN,
            engine="test-scanner",
            ctx=RequestContext(),
        )
        recorder = RecordingStorage()

        service(db_session, storage=recorder).issue_download_url(
            actor=worker["user"], file_id=record.id, ctx=RequestContext()
        )

        disposition = recorder.download_calls[0]["download_filename"]
        assert disposition == content_disposition_value(record.original_filename)
        assert disposition.startswith('attachment; filename="')
        # RFC 6266: the non-ASCII name is percent-encoded in the extended
        # parameter, so no raw byte of it reaches a header.
        assert "filename*=UTF-8''photo%C3%BC.png" in disposition
        assert "\r" not in disposition and "\n" not in disposition

    def test_an_unsafe_key_is_refused_before_the_backend_is_touched(
        self, client, db_session, worker
    ):
        """Defence in depth: the key is validated in this service, not only in Storage."""
        self._upload(client, worker)
        record = upload_record(db_session, worker["user"])
        record.scan_status = ScanStatus.CLEAN.value
        record.is_quarantined = False
        record.object_key = "../../etc/passwd.png"
        db_session.flush()
        recorder = RecordingStorage()

        with pytest.raises(ValidationError):
            service(db_session, storage=recorder).issue_download_url(
                actor=worker["user"], file_id=record.id, ctx=RequestContext()
            )

        assert recorder.download_calls == []


# --------------------------------------------------------------------------- #
# Malware scanning seam                                                       #
# --------------------------------------------------------------------------- #
class TestScanSeam:
    def test_a_non_clean_verdict_leaves_the_object_quarantined(self, client, db_session, worker):
        upload_bytes(client, worker["headers"])
        record = upload_record(db_session, worker["user"])

        service(db_session).apply_scan_result(
            file_id=record.id,
            status=ScanStatus.INFECTED,
            engine="clamav",
            ctx=RequestContext(),
        )

        assert record.is_quarantined is True
        assert record.is_downloadable is False
        assert record.scan_engine == "clamav"
        assert record.scanned_at is not None

    def test_scanning_an_unknown_file_is_a_404(self, db_session):
        with pytest.raises(NotFoundError):
            service(db_session).apply_scan_result(
                file_id=uuid.uuid4(),
                status=ScanStatus.CLEAN,
                engine="clamav",
                ctx=RequestContext(),
            )


class TestDigestIntegrity:
    def test_a_backend_that_stores_different_bytes_is_refused(self, db_session, worker):
        class WrongDigestStorage(RecordingStorage):
            def put_object(self, *, object_key: str, data: bytes, content_type: str, metadata=None):
                stored = super().put_object(
                    object_key=object_key, data=data, content_type=content_type, metadata=metadata
                )
                return type(stored)(
                    bucket=stored.bucket,
                    object_key=stored.object_key,
                    size_bytes=stored.size_bytes,
                    sha256="0" * 64,
                    etag=stored.etag,
                )

        recorder = WrongDigestStorage()

        with pytest.raises(ValidationError):
            service(db_session, storage=recorder).upload(
                actor=worker["user"], payload=upload_request(PNG), ctx=RequestContext()
            )

        assert recorder.object_exists(object_key=recorder.put_keys[0]) is False

    def test_a_failure_to_remove_a_mismatched_object_is_still_a_refusal(self, db_session, worker):
        class UndeletableStorage(RecordingStorage):
            def delete_object(self, *, object_key: str) -> None:
                raise StorageError("The file could not be deleted.")

        class WrongDigestStorage(UndeletableStorage):
            def put_object(self, *, object_key: str, data: bytes, content_type: str, metadata=None):
                stored = super().put_object(
                    object_key=object_key, data=data, content_type=content_type, metadata=metadata
                )
                return type(stored)(
                    bucket=stored.bucket,
                    object_key=stored.object_key,
                    size_bytes=stored.size_bytes,
                    sha256="0" * 64,
                    etag=stored.etag,
                )

        with pytest.raises(ValidationError):
            service(db_session, storage=WrongDigestStorage()).upload(
                actor=worker["user"], payload=upload_request(PNG), ctx=RequestContext()
            )


# --------------------------------------------------------------------------- #
# Evidence attachment                                                         #
# --------------------------------------------------------------------------- #
class TestEvidence:
    def test_an_upload_can_be_attached_to_a_project(self, client, worker, project, db_session):
        response = upload_bytes(
            client,
            worker["headers"],
            fields={
                "attach_as_evidence": "true",
                "project_id": str(project.id),
                "title": "Block C before plaster",
                "visibility": "EMPLOYERS",
            },
        )

        assert response.status_code == 201, response.text
        evidence = response.json()["data"]["evidence"]
        assert evidence["project_id"] == str(project.id)
        assert evidence["file_id"] == response.json()["data"]["file"]["id"]

        row = db_session.execute(select(EvidenceItem)).scalar_one()
        assert row.worker_profile_id == project.worker_profile_id
        assert row.title == "Block C before plaster"

    def test_evidence_is_never_more_permissive_than_the_passport(
        self, client, worker, passport, db_session
    ):
        """A PRIVATE passport asked for PUBLIC evidence gets PRIVATE evidence."""
        upload_bytes(
            client,
            worker["headers"],
            fields={"attach_as_evidence": "true", "visibility": "PUBLIC"},
        )

        row = db_session.execute(select(EvidenceItem)).scalar_one()
        assert row.visibility == EvidenceVisibility.PRIVATE.value

    def test_a_public_passport_can_carry_public_evidence(
        self, client, worker, passport, db_session
    ):
        passport.visibility = ProfileVisibility.PUBLIC.value
        db_session.flush()

        upload_bytes(
            client,
            worker["headers"],
            fields={"attach_as_evidence": "true", "visibility": "PUBLIC"},
        )

        row = db_session.execute(select(EvidenceItem)).scalar_one()
        assert row.visibility == EvidenceVisibility.PUBLIC.value

    @pytest.mark.parametrize(
        ("passport_visibility", "requested", "expected"),
        [
            ("PRIVATE", "PUBLIC", "PRIVATE"),
            ("PRIVATE", "EMPLOYERS", "PRIVATE"),
            ("DISCOVERABLE", "PUBLIC", "EMPLOYERS"),
            ("DISCOVERABLE", "EMPLOYERS", "EMPLOYERS"),
            ("PUBLIC", "PUBLIC", "PUBLIC"),
            ("PUBLIC", "PRIVATE", "PRIVATE"),
            ("SOMETHING_ELSE", "PUBLIC", "PRIVATE"),
        ],
    )
    def test_visibility_clamping(self, passport_visibility, requested, expected):
        clamped = clamp_evidence_visibility(
            EvidenceVisibility(requested), passport_visibility=passport_visibility
        )

        assert clamped.value == expected

    def test_evidence_title_defaults_to_the_sanitised_filename(
        self, client, worker, passport, db_session
    ):
        upload_bytes(
            client,
            worker["headers"],
            filename="../../etc/hoist.png",
            fields={"attach_as_evidence": "true"},
        )

        row = db_session.execute(select(EvidenceItem)).scalar_one()
        assert row.title == "hoist.png"

    def test_another_workers_project_cannot_be_used_as_a_target(
        self, client, make_user, auth_headers, project, error_code, db_session
    ):
        intruder = make_user()

        response = upload_bytes(
            client,
            auth_headers(intruder),
            fields={"attach_as_evidence": "true", "project_id": str(project.id)},
        )

        assert response.status_code == 404
        assert error_code(response) == "RESOURCE_NOT_FOUND"
        assert db_session.execute(select(FileObject)).scalars().first() is None

    def test_a_caller_without_a_passport_cannot_attach_evidence(
        self, client, worker, error_code, db_session
    ):
        response = upload_bytes(client, worker["headers"], fields={"attach_as_evidence": "true"})

        assert response.status_code == 404
        assert error_code(response) == "RESOURCE_NOT_FOUND"
        assert upload_record(db_session, worker["user"]) is None

    def test_a_failed_attachment_stores_no_object(self, db_session, worker):
        recorder = RecordingStorage()

        with pytest.raises(NotFoundError):
            service(db_session, storage=recorder).upload(
                actor=worker["user"],
                payload=upload_request(PNG, attach_as_evidence=True),
                ctx=RequestContext(),
            )

        assert recorder.put_keys == []

    def test_a_credential_target_must_belong_to_the_caller(
        self, db_session, make_user, passport, worker
    ):
        other = make_user()
        other_profile = WorkerProfile(user_id=other.id, display_name="Other")
        db_session.add(other_profile)
        db_session.flush()
        credential = Credential(worker_profile_id=other_profile.id, title="Forklift licence")
        db_session.add(credential)
        db_session.flush()

        with pytest.raises(NotFoundError):
            service(db_session).upload(
                actor=worker["user"],
                payload=upload_request(PNG, attach_as_evidence=True, credential_id=credential.id),
                ctx=RequestContext(),
            )

    def test_a_future_capture_date_is_refused(self, client, worker, passport, error_code):
        tomorrow = (datetime.now(UTC) + timedelta(days=1)).date().isoformat()

        response = upload_bytes(
            client,
            worker["headers"],
            fields={"attach_as_evidence": "true", "captured_at": tomorrow},
        )

        assert response.status_code == 422
        assert error_code(response) == "VALIDATION_FAILED"

    def test_a_captured_date_in_the_past_is_accepted(self, client, worker, passport):
        yesterday = (datetime.now(UTC) - timedelta(days=1)).date().isoformat()

        response = upload_bytes(
            client,
            worker["headers"],
            fields={"attach_as_evidence": "true", "captured_at": yesterday},
        )

        assert response.status_code == 201, response.text


# --------------------------------------------------------------------------- #
# Route inventory                                                             #
# --------------------------------------------------------------------------- #
class TestRouteSurface:
    def test_there_is_no_endpoint_that_serves_bytes_or_a_permanent_url(self):
        """A guard against a future route quietly reintroducing one.

        Three routes, and none of them returns file content. Bytes are reachable
        only through the signed, expiring URL that ``download`` returns.
        """
        paths = {(route.path, tuple(sorted(route.methods or ()))) for route in files_router.routes}

        assert paths == {
            ("/files/upload", ("POST",)),
            ("/files/{file_id}", ("GET",)),
            ("/files/{file_id}/download", ("GET",)),
        }

    def test_file_count_uses_the_files_table(self, db_session):
        assert db_session.execute(select(func.count()).select_from(FileObject)).scalar_one() == 0
