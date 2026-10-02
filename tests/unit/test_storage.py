"""Unit tests for the object-storage abstraction.

No database and, critically, **no network**: ``boto3`` is never allowed to reach
AWS. The ``S3Storage`` tests either inject a stub client or assert that a
rejected request fails before any boto call happens, so a bug that reordered a
guard behind the client construction would show up as a failure rather than as a
surprise request to a real endpoint.
"""

from __future__ import annotations

import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

from botocore.exceptions import ClientError, EndpointConnectionError
import pytest

from app.core.config import Settings
from app.core.exceptions import (
    FileTooLargeError,
    NotFoundError,
    ServiceUnavailableError,
    ValidationError,
)
from app.core.storage import (
    HARD_MAX_UPLOAD_BYTES,
    InMemoryStorage,
    S3Storage,
    Storage,
    StorageError,
    StoredObject,
    get_storage,
    reset_storage,
    validate_object_key,
)

pytestmark = pytest.mark.unit

JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32
VALID_KEY = "WORK_EVIDENCE/6f1b7f0c-2f0f-4a1d-9b6a-2c9b6c1f0a11/AbCdEf-1234567890_xyz.jpg"

BUCKET = "fundipulse-test"
#: Assembled rather than written out: these are AWS's published documentation
#: placeholders, not credentials, but a literal of this shape in the tree is
#: indistinguishable from a leaked one to a scanner and to a future reader.
ACCESS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY"
MAX_BYTES = 1024 * 1024


# --------------------------------------------------------------------------- #
# Test doubles                                                               #
# --------------------------------------------------------------------------- #
class RecordingClient:
    """A boto3 stand-in that records calls and never touches a socket."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.objects: dict[str, bytes] = {}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put_object", kwargs))
        self.objects[kwargs["Key"]] = kwargs["Body"]
        return {"ETag": '"abc123"'}

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object", kwargs))
        key = kwargs["Key"]
        if key not in self.objects:
            raise ClientError(
                {"Error": {"Code": "NoSuchKey"}},
                "GetObject",
            )
        body = self.objects[key]
        return {"Body": _FakeBody(body)}

    def delete_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("delete_object", kwargs))
        self.objects.pop(kwargs["Key"], None)
        return {}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_object", kwargs))
        if kwargs["Key"] not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": len(self.objects[kwargs["Key"]])}

    def generate_presigned_url(
        self,
        operation: str,
        Params: dict[str, Any],  # noqa: N803 - boto3's own keyword name
        ExpiresIn: int,  # noqa: N803 - boto3's own keyword name
    ) -> str:
        self.calls.append(("generate_presigned_url", {"Params": Params, "ExpiresIn": ExpiresIn}))
        # A real presigned URL is opaque and carries an AWS signature; this mimics
        # the shape (opaque token, embedded expiry) without the cryptography.
        return f"https://{BUCKET}.s3.amazonaws.com/{Params['Key']}?X-Amz-Expires={ExpiresIn}"


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


def make_s3(client: RecordingClient | None = None, **overrides: Any) -> S3Storage:
    """Build an ``S3Storage`` with a stubbed client, bypassing ``boto3`` entirely."""
    arguments: dict[str, Any] = {
        "bucket": BUCKET,
        "access_key_id": ACCESS_KEY,
        "secret_access_key": SECRET_KEY,
        "max_bytes": MAX_BYTES,
        "url_ttl_seconds": 300,
    }
    arguments.update(overrides)
    storage = S3Storage(**arguments)
    storage._client = client if client is not None else RecordingClient()
    return storage


def production_settings(**overrides: Any) -> Settings:
    """Build a ``Settings`` that satisfies the production posture validator.

    Every field the validator insists on is set explicitly, because the process
    environment (and ``.env``) otherwise leak in: the test suite sets
    ``RATE_LIMIT_ENABLED=false``, which a production ``Settings`` must refuse.
    """
    arguments: dict[str, Any] = {
        "app_env": "production",
        "secret_key": "a-production-secret-key-of-32-plus-chars",
        "jwt_secret": "a-different-production-jwt-secret-32-plus-chars",
        "cors_allowed_origins": ["https://app.fundipulse.co.ke"],
        "database_url": "postgresql+psycopg://appuser:realsecret@db.internal:5432/fundipulse",
        "storage_backend": "memory",
        "enable_docs": False,
        "debug": False,
        "rate_limit_enabled": True,
        "database_echo": False,
        "sentry_dsn": "",
    }
    arguments.update(overrides)
    return Settings(**arguments)


# --------------------------------------------------------------------------- #
# In-memory backend                                                          #
# --------------------------------------------------------------------------- #
class TestInMemoryStorageRoundTrip:
    def test_round_trips_put_get_exists_delete(self) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        stored = storage.put_object(
            object_key=VALID_KEY,
            data=JPEG_BYTES,
            content_type="image/jpeg",
        )

        assert isinstance(stored, StoredObject)
        assert stored.bucket == BUCKET
        assert stored.object_key == VALID_KEY
        assert stored.size_bytes == len(JPEG_BYTES)
        assert stored.sha256 == __import__("hashlib").sha256(JPEG_BYTES).hexdigest()
        assert storage.get_object(object_key=VALID_KEY) == JPEG_BYTES
        assert storage.object_exists(object_key=VALID_KEY) is True

        storage.delete_object(object_key=VALID_KEY)

        assert storage.object_exists(object_key=VALID_KEY) is False
        with pytest.raises(NotFoundError):
            storage.get_object(object_key=VALID_KEY)

    def test_missing_object_is_a_not_found_not_a_crash(self) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        with pytest.raises(NotFoundError):
            storage.get_object(object_key="WORK_EVIDENCE/absent/key.jpg")

    def test_delete_is_idempotent(self) -> None:
        """Deleting twice is not an error, matching how S3 behaves.

        A retried request after a partially-applied deletion must not 500.
        """
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)
        storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")

        storage.delete_object(object_key=VALID_KEY)
        storage.delete_object(object_key=VALID_KEY)

        assert storage.object_exists(object_key=VALID_KEY) is False

    def test_stored_bytes_cannot_be_mutated_through_a_returned_value(self) -> None:
        """A caller cannot reach in and alter what is stored.

        ``bytes`` is immutable, which is the whole mechanism, but the guarantee is
        worth pinning: a backend that stored a ``bytearray`` would let one request
        rewrite another request's upload.
        """
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)
        storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")

        returned = storage.get_object(object_key=VALID_KEY)

        assert isinstance(returned, bytes)
        assert returned == JPEG_BYTES
        # A mutable view of the returned bytes is a fresh buffer, not the store.
        buffer = bytearray(returned)
        buffer[0] = 0
        assert storage.get_object(object_key=VALID_KEY) == JPEG_BYTES

    def test_put_overwrites_an_existing_key(self) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)
        storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")

        replacement = JPEG_BYTES + b"second version"
        storage.put_object(object_key=VALID_KEY, data=replacement, content_type="image/jpeg")

        assert storage.get_object(object_key=VALID_KEY) == replacement

    def test_metadata_is_accepted_and_not_leaked_into_the_bytes(self) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        stored = storage.put_object(
            object_key=VALID_KEY,
            data=JPEG_BYTES,
            content_type="image/jpeg",
            metadata={"owner-id": "user-1"},
        )

        assert stored.size_bytes == len(JPEG_BYTES)
        assert storage.get_object(object_key=VALID_KEY) == JPEG_BYTES

    def test_is_a_storage_implementation(self) -> None:
        """The factory's return type is the abstract base, so either backend fits."""
        assert isinstance(InMemoryStorage(bucket=BUCKET), Storage)

    def test_reports_its_own_limits(self) -> None:
        """Callers can read the ceiling rather than duplicating the clamping rules."""
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=1234, url_ttl_seconds=77)

        assert storage.max_bytes == 1234
        assert storage.url_ttl_seconds == 77
        assert storage.bucket == BUCKET

    def test_defaults_the_bucket_when_configuration_names_none(self) -> None:
        """A dev backend with no bucket configured still needs a name to report."""
        assert InMemoryStorage().bucket == "fundipulse-local"


class TestInMemoryStorageLimits:
    def test_enforces_the_configured_size_ceiling(self) -> None:
        """The ceiling is enforced at the write, not only in the upload route.

        A caller that reaches ``put_object`` by another path still cannot write an
        object the schema would refuse to record.
        """
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=len(JPEG_BYTES))

        storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")
        with pytest.raises(FileTooLargeError):
            storage.put_object(
                object_key=f"{VALID_KEY}-big",
                data=JPEG_BYTES + b"0" * 10,
                content_type="image/jpeg",
            )

    def test_rejects_an_empty_object(self) -> None:
        """A zero-byte object would violate ``files_size_within_hard_cap``."""
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        with pytest.raises(ValidationError):
            storage.put_object(object_key=VALID_KEY, data=b"", content_type="image/jpeg")

    def test_rejects_a_missing_content_type(self) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        with pytest.raises(ValidationError):
            storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="")

    def test_rejects_a_content_type_carrying_header_parameters(self) -> None:
        """A stored ``Content-Type`` is served back to browsers; it must be inert."""
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        with pytest.raises(ValidationError):
            storage.put_object(
                object_key=VALID_KEY,
                data=JPEG_BYTES,
                content_type="image/jpeg; charset=utf-8",
            )

    @pytest.mark.parametrize(
        "object_key",
        [
            "../../etc/passwd",
            "WORK_EVIDENCE/../../secrets.jpg",
            "/absolute/key.jpg",
            "WORK_EVIDENCE\\owner\\key.jpg",
            "WORK_EVIDENCE/owner/key\x00.jpg",
            "https://evil.example/key.jpg",
        ],
    )
    def test_rejects_unsafe_object_keys_on_every_method(self, object_key: str) -> None:
        """The in-memory backend applies the same guard as the S3 one.

        Tests written only against the production backend let a permissive
        development backend ship a hole that is then "fixed" by never running the
        dangerous path in development.
        """
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        for call in (
            lambda: storage.put_object(
                object_key=object_key, data=JPEG_BYTES, content_type="image/jpeg"
            ),
            lambda: storage.get_object(object_key=object_key),
            lambda: storage.delete_object(object_key=object_key),
            lambda: storage.object_exists(object_key=object_key),
            lambda: storage.create_download_url(object_key=object_key),
        ):
            with pytest.raises(ValidationError):
                call()


class TestInMemoryStorageUrls:
    def test_generated_url_is_opaque(self) -> None:
        """The object key must not be readable from the URL.

        A URL that names its object is one that gets pasted into a support ticket.
        The HMAC form keeps the key server-side.
        """
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        url = storage.create_download_url(object_key=VALID_KEY)

        assert VALID_KEY not in url
        assert "/download" in url

    def test_two_urls_for_one_key_differ(self) -> None:
        """Expiry is part of the signed material, so URLs are not replayable at will."""
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        first = storage.create_download_url(object_key=VALID_KEY, expires_in=60)
        time.sleep(1)
        second = storage.create_download_url(object_key=VALID_KEY, expires_in=60)

        assert first != second

    def test_url_carries_a_bounded_expiry(self) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES, url_ttl_seconds=300)

        url = storage.create_download_url(object_key=VALID_KEY)
        query = parse_qs(urlsplit(url).query)
        expires_at = int(query["expires"][0])

        assert expires_at <= int(time.time()) + 300
        assert expires_at > int(time.time())

    def test_a_longer_requested_expiry_is_clamped(self) -> None:
        """A caller cannot ask for a URL that outlives the configured ceiling.

        A signed URL nobody remembers to revoke is a standing credential.
        """
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES, url_ttl_seconds=60)

        query = parse_qs(
            urlsplit(storage.create_download_url(object_key=VALID_KEY, expires_in=999_999)).query
        )

        assert int(query["expires"][0]) <= int(time.time()) + 60

    def test_a_shorter_requested_expiry_is_honoured(self) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES, url_ttl_seconds=3600)

        query = parse_qs(
            urlsplit(storage.create_download_url(object_key=VALID_KEY, expires_in=45)).query
        )

        assert int(query["expires"][0]) <= int(time.time()) + 45

    @pytest.mark.parametrize("expires_in", [0, -1])
    def test_rejects_a_non_positive_expiry(self, expires_in: int) -> None:
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES)

        with pytest.raises(ValidationError):
            storage.create_download_url(object_key=VALID_KEY, expires_in=expires_in)


class TestInMemoryStorageConcurrency:
    def test_concurrent_writers_do_not_corrupt_the_store(self) -> None:
        """The lock is what makes this usable inside a multi-threaded worker.

        Without it a read-modify-write in ``put_object`` can interleave and leave a
        half-written entry, which in development looks like a flaky test and in
        production would look like a corrupted upload.
        """
        storage = InMemoryStorage(bucket=BUCKET, max_bytes=MAX_BYTES * 10)
        errors: list[BaseException] = []

        def _write(index: int) -> None:
            try:
                for _ in range(20):
                    key = f"WORK_EVIDENCE/owner-{index}/key-{index}.jpg"
                    storage.put_object(
                        object_key=key,
                        data=JPEG_BYTES + bytes([index % 256]),
                        content_type="image/jpeg",
                    )
                    assert storage.object_exists(object_key=key)
            except BaseException as exc:  # noqa: BLE001 - recorded and re-raised below
                errors.append(exc)

        threads = [threading.Thread(target=_write, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, errors
        assert len(storage._objects) == 8


# --------------------------------------------------------------------------- #
# S3 backend: construction                                                   #
# --------------------------------------------------------------------------- #
class TestS3StorageConstruction:
    def test_construction_performs_no_network_io(self) -> None:
        """Building the backend must not open a connection or read instance metadata.

        A credential lookup at import time means a slow cold start and, in an
        environment with no metadata endpoint, a multi-second hang before the first
        request.
        """
        storage = S3Storage(
            bucket=BUCKET,
            access_key_id=ACCESS_KEY,
            secret_access_key=SECRET_KEY,
        )

        assert storage._client is None

    @pytest.mark.parametrize(
        ("overrides", "expected_fragment"),
        [
            pytest.param(
                {"bucket": ""},
                "STORAGE_BUCKET",
                id="missing-bucket",
            ),
            pytest.param(
                {"access_key_id": ""},
                "STORAGE_ACCESS_KEY",
                id="missing-access-key",
            ),
            pytest.param(
                {"secret_access_key": ""},
                "STORAGE_SECRET_KEY",
                id="missing-secret-key",
            ),
        ],
    )
    def test_fails_clearly_when_configuration_is_missing(
        self, overrides: dict[str, str], expected_fragment: str
    ) -> None:
        """A misconfigured deployment fails at boot, not on the first upload.

        The message names the setting, because the operator reading a 503 needs to
        know which variable to set.
        """
        arguments: dict[str, Any] = {
            "bucket": BUCKET,
            "access_key_id": ACCESS_KEY,
            "secret_access_key": SECRET_KEY,
        }
        arguments.update(overrides)

        with pytest.raises(ServiceUnavailableError) as caught:
            S3Storage(**arguments)

        assert expected_fragment in caught.value.message

    def test_reports_the_configured_bucket(self) -> None:
        storage = make_s3()

        assert storage.bucket == BUCKET

    def test_clamps_the_size_ceiling_to_the_schema_hard_cap(self) -> None:
        """A ceiling above the CHECK constraint would fail at insert time."""
        storage = make_s3(max_bytes=HARD_MAX_UPLOAD_BYTES * 4)

        with pytest.raises(FileTooLargeError):
            storage.put_object(
                object_key=VALID_KEY,
                data=b"\xff\xd8\xff" + b"0" * (HARD_MAX_UPLOAD_BYTES),
                content_type="image/jpeg",
            )


# --------------------------------------------------------------------------- #
# S3 backend: dangerous keys must never reach boto                             #
# --------------------------------------------------------------------------- #
class TestS3StorageRejectsDangerousKeys:
    @pytest.mark.parametrize(
        ("object_key", "label"),
        [
            pytest.param("../other-owner/secret.jpg", "parent-traversal", id="dot-dot-prefix"),
            pytest.param("WORK_EVIDENCE/../../../secrets.jpg", "traversal", id="traversal-middle"),
            pytest.param("WORK_EVIDENCE/owner/..", "trailing-traversal", id="trailing-dot-dot"),
            pytest.param("/WORK_EVIDENCE/owner/key.jpg", "leading-slash", id="leading-slash"),
            pytest.param("WORK_EVIDENCE\\owner\\key.jpg", "backslash", id="backslash"),
            pytest.param("WORK_EVIDENCE/owner/key\x00.jpg", "nul-byte", id="nul-byte"),
            pytest.param("https://evil.example/key.jpg", "https", id="scheme-https"),
            pytest.param("s3://other-bucket/key.jpg", "s3-scheme", id="scheme-s3"),
            pytest.param("file:/etc/passwd", "single slash scheme", id="scheme-file"),
            pytest.param("data:text/html,<script>", "data uri", id="scheme-data"),
            pytest.param("mailto:a@b.example", "mailto", id="scheme-mailto"),
            pytest.param("", "empty", id="empty"),
            pytest.param("WORK_EVIDENCE//owner/key.jpg", "empty-segment", id="double-slash"),
            pytest.param("WORK_EVIDENCE/owner/key\nX-Injected.jpg", "control-char", id="newline"),
            pytest.param(f"WORK_EVIDENCE/{'a' * 600}/key.jpg", "over-long", id="too-long"),
        ],
    )
    def test_rejected_before_any_boto_call(self, object_key: str, label: str) -> None:
        """The guard runs first, so a signing bug cannot become an arbitrary read.

        Every entry point is checked, because the read path is the one that
        matters: a key that escaped validation on ``get_object`` or
        ``create_download_url`` would hand out somebody else's bytes.
        """
        client = RecordingClient()
        storage = make_s3(client)

        with pytest.raises(ValidationError, match=None):
            storage.put_object(object_key=object_key, data=JPEG_BYTES, content_type="image/jpeg")
        with pytest.raises(ValidationError):
            storage.get_object(object_key=object_key)
        with pytest.raises(ValidationError):
            storage.delete_object(object_key=object_key)
        with pytest.raises(ValidationError):
            storage.object_exists(object_key=object_key)
        with pytest.raises(ValidationError):
            storage.create_download_url(object_key=object_key)

        assert client.calls == [], f"boto was reached for {label}"

    def test_a_safe_key_does_reach_boto(self) -> None:
        """The guard is not simply refusing everything.

        A rejection that never calls boto would pass the dangerous-key test for the
        wrong reason, so the safe case is asserted too.
        """
        client = RecordingClient()
        storage = make_s3(client)
        client.objects[VALID_KEY] = JPEG_BYTES

        assert storage.get_object(object_key=VALID_KEY) == JPEG_BYTES
        assert [name for name, _ in client.calls] == ["get_object"]

    def test_validation_is_a_separate_importable_check(self) -> None:
        """Exposed so other layers can assert a key's provenance without a client."""
        assert validate_object_key(VALID_KEY) == VALID_KEY
        with pytest.raises(ValidationError):
            validate_object_key("../escape.jpg")


# --------------------------------------------------------------------------- #
# S3 backend: behaviour against the stub client                              #
# --------------------------------------------------------------------------- #
class TestS3StorageBehaviour:
    def test_put_encrypts_server_side(self) -> None:
        """Private plus encrypted at rest: a leaked bucket is still not readable."""
        client = RecordingClient()
        storage = make_s3(client)

        stored = storage.put_object(
            object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg"
        )

        _, arguments = client.calls[0]
        assert arguments["ServerSideEncryption"] == "AES256"
        assert arguments["ContentType"] == "image/jpeg"
        assert stored.etag == "abc123"

    def test_get_round_trips(self) -> None:
        client = RecordingClient()
        storage = make_s3(client)
        storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")

        assert storage.get_object(object_key=VALID_KEY) == JPEG_BYTES

    def test_get_missing_object_is_a_not_found(self) -> None:
        client = RecordingClient()
        storage = make_s3(client)

        with pytest.raises(NotFoundError):
            storage.get_object(object_key=VALID_KEY)

    def test_exists_reflects_absence(self) -> None:
        client = RecordingClient()
        storage = make_s3(client)

        assert storage.object_exists(object_key=VALID_KEY) is False

        storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")

        assert storage.object_exists(object_key=VALID_KEY) is True

    def test_delete_removes_the_object(self) -> None:
        client = RecordingClient()
        storage = make_s3(client)
        storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")

        storage.delete_object(object_key=VALID_KEY)

        assert storage.object_exists(object_key=VALID_KEY) is False

    def test_backend_failure_becomes_a_storage_error(self) -> None:
        """A botocore failure is an outage, not a client mistake.

        Reporting it as a 400 would invite the client to retry something that
        cannot succeed, and the botocore message carries bucket names that have
        no business in an API response.
        """
        client = RecordingClient()

        def _explode(**_kwargs: Any) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "InternalError"}}, "PutObject")

        client.put_object = _explode  # type: ignore[method-assign]
        storage = make_s3(client)

        with pytest.raises(StorageError) as caught:
            storage.put_object(object_key=VALID_KEY, data=JPEG_BYTES, content_type="image/jpeg")

        assert "InternalError" not in caught.value.message

    def test_download_url_pins_the_content_type(self) -> None:
        """The browser must not be left to sniff what the bytes are.

        Sniffing on download is how a stored document becomes script executed in
        our own origin. Pinning the type means the decision was made by the code
        that validated the bytes.
        """
        client = RecordingClient()
        storage = make_s3(client)

        storage.create_download_url(object_key=VALID_KEY, content_type="image/jpeg")

        arguments = client.calls[-1][1]
        assert arguments["Params"]["ResponseContentType"] == "image/jpeg"
        assert arguments["Params"]["ResponseContentDisposition"] == "attachment"

    def test_download_url_falls_back_to_an_opaque_type(self) -> None:
        client = RecordingClient()
        storage = make_s3(client)

        storage.create_download_url(object_key=VALID_KEY)

        arguments = client.calls[-1][1]
        assert arguments["Params"]["ResponseContentType"] == "application/octet-stream"

    def test_download_url_is_expiry_bounded(self) -> None:
        client = RecordingClient()
        storage = make_s3(client, url_ttl_seconds=120)

        storage.create_download_url(object_key=VALID_KEY, expires_in=999_999)

        arguments = client.calls[-1][1]
        assert arguments["ExpiresIn"] == 120

    def test_download_filename_overrides_the_disposition(self) -> None:
        """An escaped value from ``content_disposition_value`` reaches the response.

        The caller owns escaping: this layer passes the string through, because a
        layer that "helpfully" escaped again would double-encode a correct value.
        """
        client = RecordingClient()
        storage = make_s3(client)

        storage.create_download_url(
            object_key=VALID_KEY,
            download_filename='attachment; filename="photo.jpg"',
            content_type="image/jpeg",
        )

        arguments = client.calls[-1][1]
        assert arguments["Params"]["ResponseContentDisposition"] == (
            'attachment; filename="photo.jpg"'
        )

    def test_put_passes_metadata_through(self) -> None:
        client = RecordingClient()
        storage = make_s3(client)

        storage.put_object(
            object_key=VALID_KEY,
            data=JPEG_BYTES,
            content_type="image/jpeg",
            metadata={"scan-status": "clean"},
        )

        _, arguments = client.calls[-1]
        assert arguments["Metadata"] == {"scan-status": "clean"}

    @pytest.mark.parametrize(
        "failing",
        ["delete_object", "head_object", "generate_presigned_url"],
    )
    def test_every_operation_maps_a_backend_failure_to_a_storage_error(self, failing: str) -> None:
        """No boto error escapes untyped.

        An unhandled ``ClientError`` becomes a 500 with a stack trace and a bucket
        name in it; the API contract says storage trouble is a clean 503.
        """

        def _explode(*_args: Any, **_kwargs: Any) -> Any:
            raise ClientError({"Error": {"Code": "InternalError"}}, failing)

        client = RecordingClient()
        setattr(client, failing, _explode)
        storage = make_s3(client)

        with pytest.raises(StorageError):
            if failing == "delete_object":
                storage.delete_object(object_key=VALID_KEY)
            elif failing == "head_object":
                storage.object_exists(object_key=VALID_KEY)
            else:
                storage.create_download_url(object_key=VALID_KEY)

    def test_exists_maps_a_non_missing_client_error_to_a_storage_error(self) -> None:
        """``False`` must mean "absent", never "the backend was unreachable".

        Returning ``False`` for an outage would have the upload path believe the
        object is gone and overwrite the metadata row.
        """

        def _explode(**_kwargs: Any) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "InternalError"}}, "HeadObject")

        client = RecordingClient()
        client.head_object = _explode  # type: ignore[method-assign]
        storage = make_s3(client)

        with pytest.raises(StorageError):
            storage.object_exists(object_key=VALID_KEY)

    def test_the_client_is_built_once_and_lazily(self) -> None:
        """A cached client, built on first use.

        ``boto3`` clients are expensive to construct and safe to share, and building
        one during module import would read instance metadata at import time.
        """
        storage = S3Storage(bucket=BUCKET, access_key_id=ACCESS_KEY, secret_access_key=SECRET_KEY)

        assert storage._client is None

        first = storage.client
        second = storage.client

        assert first is second

    def test_rejects_a_content_type_that_is_too_long(self) -> None:
        """``files.content_type`` is ``String(120)``; anything longer cannot be stored."""
        storage = make_s3()

        with pytest.raises(ValidationError):
            storage.put_object(
                object_key=VALID_KEY,
                data=JPEG_BYTES,
                content_type="image/jpeg" + "x" * 200,
            )

    def test_get_maps_a_non_missing_client_error_to_a_storage_error(self) -> None:
        """Only a genuinely absent key becomes a 404.

        Every other botocore error means the read failed, and reporting that as
        "not found" would invite a client to delete metadata for a file that is
        still there.
        """

        def _explode(**_kwargs: Any) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "SlowDown"}}, "GetObject")

        client = RecordingClient()
        client.get_object = _explode  # type: ignore[method-assign]
        storage = make_s3(client)

        with pytest.raises(StorageError) as caught:
            storage.get_object(object_key=VALID_KEY)

        assert not isinstance(caught.value, NotFoundError)

    @pytest.mark.parametrize("failing", ["get_object", "head_object"])
    def test_a_transport_failure_is_a_storage_error_not_a_missing_object(
        self, failing: str
    ) -> None:
        """A connection error must not be reported as "the file does not exist".

        ``NoSuchKey`` and "the socket died" are both botocore exceptions, and
        conflating them means an upload route deletes its metadata row because the
        network blipped.
        """

        def _explode(*_args: Any, **_kwargs: Any) -> Any:
            raise EndpointConnectionError(endpoint_url="https://s3.invalid")

        client = RecordingClient()
        setattr(client, failing, _explode)
        storage = make_s3(client)

        with pytest.raises(StorageError) as caught:
            if failing == "get_object":
                storage.get_object(object_key=VALID_KEY)
            else:
                storage.object_exists(object_key=VALID_KEY)

        assert not isinstance(caught.value, NotFoundError)

    def test_reports_its_own_limits(self) -> None:
        """Callers can read the ceiling rather than duplicating the clamping rules."""
        storage = make_s3(max_bytes=1234, url_ttl_seconds=77)

        assert storage.max_bytes == 1234
        assert storage.url_ttl_seconds == 77

    def test_the_client_is_built_once_under_concurrency(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two threads racing on first use must not build two clients.

        ``boto3`` clients are expensive and safe to share. Building two means
        duplicated credential resolution and connection pools; worse, it is the
        kind of bug that only appears under production load.
        """
        import app.core.storage as storage_module

        built: list[object] = []
        build_lock = threading.Lock()

        def _fake_client(*_args: Any, **_kwargs: Any) -> object:
            # Widen the race window deterministically instead of hoping for it.
            time.sleep(0.01)
            sentinel = object()
            with build_lock:
                built.append(sentinel)
            return sentinel

        monkeypatch.setattr(storage_module.boto3, "client", _fake_client)
        storage = S3Storage(bucket=BUCKET, access_key_id=ACCESS_KEY, secret_access_key=SECRET_KEY)

        results: list[object] = []
        threads = [
            threading.Thread(target=lambda: results.append(storage.client)) for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(built) == 1
        assert len(results) == 8
        assert all(client is built[0] for client in results)

    def test_clamps_a_ttl_below_the_floor(self) -> None:
        """A one-second URL is unusable on a slow connection.

        ``signed_url_ttl_seconds`` is validated at 30 or above by settings, but a
        backend constructed directly should not be able to mint a URL that is
        already dead on arrival.
        """
        storage = make_s3(url_ttl_seconds=1)

        assert storage.url_ttl_seconds == 30


# --------------------------------------------------------------------------- #
# Factory                                                                    #
# --------------------------------------------------------------------------- #
class TestGetStorageFactory:
    def test_refuses_in_memory_storage_in_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ephemeral storage in production silently loses every uploaded document.

        The API would accept the upload, report success, and serve a 404 after the
        next restart or from a second worker. Refusing to start turns silent data
        loss into a deployment that does not come up.
        """
        reset_storage()
        monkeypatch.setattr(
            "app.core.storage.get_settings",
            lambda: production_settings(storage_backend="memory"),
        )

        try:
            with pytest.raises(ServiceUnavailableError) as caught:
                get_storage()
        finally:
            reset_storage()

        assert "STORAGE_BACKEND=s3" in caught.value.message

    def test_the_backend_constructor_also_refuses_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Belt and braces: the refusal is not only in the factory.

        Anyone constructing the backend directly - a script, a management command -
        must not be able to sidestep the check.
        """
        monkeypatch.setattr("app.core.storage.get_settings", lambda: production_settings())

        with pytest.raises(ServiceUnavailableError):
            InMemoryStorage()

    def test_builds_the_s3_backend_from_configuration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reset_storage()
        settings = production_settings(
            storage_backend="s3",
            storage_bucket=BUCKET,
            storage_access_key=ACCESS_KEY,
            storage_secret_key=SECRET_KEY,
        )
        monkeypatch.setattr("app.core.storage.get_settings", lambda: settings)

        try:
            storage = get_storage()
        finally:
            reset_storage()

        assert isinstance(storage, S3Storage)
        assert storage.bucket == BUCKET

    def test_builds_the_memory_backend_in_development(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reset_storage()
        monkeypatch.setattr(
            "app.core.storage.get_settings",
            lambda: Settings(app_env="development", storage_backend="memory"),
        )

        try:
            storage = get_storage()
        finally:
            reset_storage()

        assert isinstance(storage, InMemoryStorage)

    def test_caches_the_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One backend per process: building a boto3 client per request is wasteful."""
        reset_storage()
        monkeypatch.setattr(
            "app.core.storage.get_settings",
            lambda: Settings(app_env="test", storage_backend="memory"),
        )

        try:
            first = get_storage()
            second = get_storage()
        finally:
            reset_storage()

        assert first is second

    def test_reset_rebuilds_the_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configuration changes and tests both need a fresh backend."""
        reset_storage()
        monkeypatch.setattr(
            "app.core.storage.get_settings",
            lambda: Settings(app_env="test", storage_backend="memory"),
        )

        try:
            first = get_storage()
            reset_storage()
            second = get_storage()
        finally:
            reset_storage()

        assert first is not second
