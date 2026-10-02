"""Object storage: the only path to file bytes."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Any, Final
from urllib.parse import quote, urlencode

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import get_settings
from app.core.exceptions import (
    ErrorCode,
    FileTooLargeError,
    NotFoundError,
    ServiceUnavailableError,
    ValidationError,
)
from app.core.logging import get_logger

logger = get_logger(__name__)

#: Bucket name used by the in-memory backend when configuration does not name
#: one. Never a real bucket: the whole point of that backend is that there is no
#: real bucket.
DEFAULT_MEMORY_BUCKET: Final[str] = "fundipulse-local"

#: Served instead of a sniffed type when a caller does not supply one. Telling
#: the browser "this is an opaque byte stream" removes its licence to decide what
#: the bytes are; the allowlist already excludes HTML and SVG, and this closes the
#: gap for anything reached through a path that forgot to pass a type.
SAFE_FALLBACK_CONTENT_TYPE: Final[str] = "application/octet-stream"

#: Mirrors ``CHECK (size_bytes > 0 AND size_bytes <= 26214400)`` on ``files``.
#: Re-checked here because this is the last line of defence before bytes are
#: written; the schema is the backstop, not the primary control.
HARD_MAX_UPLOAD_BYTES: Final[int] = 25 * 1024 * 1024

#: Matches ``files.object_key``.
MAX_OBJECT_KEY_LENGTH: Final[int] = 512

#: Matches ``files.content_type``. Longer than any real type by a wide margin.
MAX_CONTENT_TYPE_LENGTH: Final[int] = 120

#: Lower bound on a signed URL's lifetime. A URL that expires in seconds is
#: unusable on a slow connection, and a caller-supplied ``expires_in=1`` should
#: not become a way to confuse a client.
MIN_SIGNED_URL_TTL_SECONDS: Final[int] = 30

#: ``scheme:`` at the start of a key. An S3 key is a name inside a bucket, so a
#: scheme prefix can only mean someone is trying to point the signing code at a
#: different endpoint.
_SCHEME_LIKE_PREFIX: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")

#: Control characters, including NUL. S3 keys may technically contain them, so
#: their presence means the value did not come from a key generator.
_CONTROL_CHARACTERS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_CLIENT_ERROR_CODES: Final[frozenset[str]] = frozenset({"404", "NoSuchKey", "NoSuchBucket", "403"})


class StorageError(ServiceUnavailableError):
    """A storage backend operation failed."""

    code = ErrorCode.SERVICE_UNAVAILABLE


@dataclass(frozen=True, slots=True)
class StoredObject:
    """What the backend recorded for one object."""

    bucket: str
    object_key: str
    size_bytes: int
    sha256: str
    etag: str | None = None


class Storage(abc.ABC):
    """Abstract object-storage client."""

    @property
    @abc.abstractmethod
    def bucket(self) -> str:
        """The bucket this instance reads and writes."""

    @abc.abstractmethod
    def put_object(
        self,
        *,
        object_key: str,
        data: bytes,
        content_type: str,
        metadata: dict[str, str] | None = None,
    ) -> StoredObject:
        """Store ``data`` at ``object_key`` and return what was recorded. Args: object_key: A server..."""

    @abc.abstractmethod
    def get_object(self, *, object_key: str) -> bytes:
        """Return the bytes stored at ``object_key``. Raises: NotFoundError: No such object. Validat..."""

    @abc.abstractmethod
    def delete_object(self, *, object_key: str) -> None:
        """Remove the object at ``object_key``, if it exists. Raises: ValidationError: The key is un..."""

    @abc.abstractmethod
    def object_exists(self, *, object_key: str) -> bool:
        """Whether an object exists at ``object_key``. Raises: ValidationError: The key is unsafe. S..."""

    @abc.abstractmethod
    def create_download_url(
        self,
        *,
        object_key: str,
        expires_in: int | None = None,
        download_filename: str | None = None,
        content_type: str | None = None,
    ) -> str:
        """Return a time-limited URL that grants read access to one object. Args: object_key: A serv..."""


class InMemoryStorage(Storage):
    """A working backend held in a dict, for development and tests."""

    def __init__(
        self,
        *,
        bucket: str | None = None,
        max_bytes: int | None = None,
        url_ttl_seconds: int | None = None,
        allow_in_production: bool = False,
    ) -> None:
        """Create an empty backend. Args: bucket: Bucket name to report. Defaults to a local-only pl..."""
        settings = get_settings()
        if settings.is_production and not allow_in_production:
            raise ServiceUnavailableError(
                "In-memory storage is not available in production; configure S3."
            )

        self._bucket = bucket or DEFAULT_MEMORY_BUCKET
        configured_max = settings.max_upload_size_bytes if max_bytes is None else max_bytes
        self._max_bytes = max(1, min(configured_max, HARD_MAX_UPLOAD_BYTES))
        configured_ttl = (
            settings.signed_url_ttl_seconds if url_ttl_seconds is None else url_ttl_seconds
        )
        self._url_ttl_seconds = max(MIN_SIGNED_URL_TTL_SECONDS, configured_ttl)
        # Per-process signing secret. Ephemeral by definition: restarting the
        # process invalidates outstanding URLs, which is exactly what happens to
        # real signed URLs when credentials rotate.
        self._signing_secret = secrets.token_bytes(32)
        self._objects: dict[str, bytes] = {}
        self._metadata: dict[str, dict[str, str]] = {}
        self._lock = threading.RLock()

    @property
    def bucket(self) -> str:
        return self._bucket

    @property
    def max_bytes(self) -> int:
        """The per-object ceiling this instance enforces."""
        return self._max_bytes

    @property
    def url_ttl_seconds(self) -> int:
        """The longest lifetime a signed URL from this instance may claim."""
        return self._url_ttl_seconds

    def put_object(
        self,
        *,
        object_key: str,
        data: bytes,
        content_type: str,
        metadata: dict[str, str] | None = None,
    ) -> StoredObject:
        validate_object_key(object_key)
        validate_object_size(data, max_bytes=self._max_bytes)
        validate_content_type(content_type)
        digest = hashlib.sha256(data).hexdigest()
        with self._lock:
            self._objects[object_key] = bytes(data)
            self._metadata[object_key] = dict(metadata or {})
        logger.info(
            "storage.object_stored",
            extra={"bucket": self._bucket, "object_key": object_key, "size": len(data)},
        )
        # The etag is the sha256 rather than an MD5: nothing consumes it as an
        # S3-compatible integrity value here, and MD5 buys nothing.
        return StoredObject(
            bucket=self._bucket,
            object_key=object_key,
            size_bytes=len(data),
            sha256=digest,
            etag=digest,
        )

    def get_object(self, *, object_key: str) -> bytes:
        validate_object_key(object_key)
        with self._lock:
            data = self._objects.get(object_key)
        if data is None:
            raise NotFoundError("That file is no longer available.")
        return data

    def delete_object(self, *, object_key: str) -> None:
        validate_object_key(object_key)
        with self._lock:
            existed = self._objects.pop(object_key, None) is not None
            self._metadata.pop(object_key, None)
        if existed:
            logger.info(
                "storage.object_deleted",
                extra={"bucket": self._bucket, "object_key": object_key},
            )

    def object_exists(self, *, object_key: str) -> bool:
        validate_object_key(object_key)
        with self._lock:
            return object_key in self._objects

    def create_download_url(
        self,
        *,
        object_key: str,
        expires_in: int | None = None,
        download_filename: str | None = None,
        content_type: str | None = None,
    ) -> str:
        validate_object_key(object_key)
        ttl = _clamp_ttl(expires_in, self._url_ttl_seconds)
        expires_at = int(time.time()) + ttl
        token = self._sign(object_key, expires_at, download_filename, content_type)
        query = urlencode({"expires": str(expires_at), "token": token})
        return f"memory://{quote(self._bucket)}/download?{query}"

    def _sign(
        self,
        object_key: str,
        expires_at: int,
        download_filename: str | None,
        content_type: str | None,
    ) -> str:
        """Bind a token to one key, one expiry and the response overrides."""
        message = "\n".join(
            [
                object_key,
                str(expires_at),
                download_filename or "",
                content_type or SAFE_FALLBACK_CONTENT_TYPE,
            ]
        )
        return hmac.new(self._signing_secret, message.encode(), hashlib.sha256).hexdigest()[:32]


class S3Storage(Storage):
    """The production backend, over ``boto3``."""

    def __init__(
        self,
        *,
        bucket: str,
        access_key_id: str,
        secret_access_key: str,
        region: str = "af-south-1",
        endpoint_url: str | None = None,
        use_path_style: bool = False,
        max_bytes: int | None = None,
        url_ttl_seconds: int | None = None,
    ) -> None:
        """Validate configuration and record it. No I/O happens here. Raises: ServiceUnavailableErro..."""
        if not bucket:
            raise ServiceUnavailableError(
                "Object storage is not configured: STORAGE_BUCKET is required for the s3 backend."
            )
        if not access_key_id:
            raise ServiceUnavailableError(
                "Object storage is not configured: STORAGE_ACCESS_KEY is required for the s3 backend."
            )
        if not secret_access_key:
            raise ServiceUnavailableError(
                "Object storage is not configured: STORAGE_SECRET_KEY is required for the s3 backend."
            )

        self._bucket = bucket
        self._region = region
        self._endpoint_url = endpoint_url
        self._use_path_style = use_path_style
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        configured_max = get_settings().max_upload_size_bytes if max_bytes is None else max_bytes
        self._max_bytes = max(1, min(configured_max, HARD_MAX_UPLOAD_BYTES))
        configured_ttl = (
            get_settings().signed_url_ttl_seconds if url_ttl_seconds is None else url_ttl_seconds
        )
        self._url_ttl_seconds = max(MIN_SIGNED_URL_TTL_SECONDS, configured_ttl)
        self._client: BaseClient | None = None
        self._client_lock = threading.Lock()

    @property
    def bucket(self) -> str:
        return self._bucket

    @property
    def max_bytes(self) -> int:
        """The per-object ceiling this instance enforces."""
        return self._max_bytes

    @property
    def url_ttl_seconds(self) -> int:
        """The longest lifetime a presigned URL from this instance may claim."""
        return self._url_ttl_seconds

    @property
    def client(self) -> BaseClient:
        """The lazily constructed ``boto3`` S3 client."""
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    self._client = boto3.client(
                        "s3",
                        region_name=self._region,
                        endpoint_url=self._endpoint_url,
                        aws_access_key_id=self._access_key_id,
                        aws_secret_access_key=self._secret_access_key,
                        config=_client_config(self._use_path_style),
                    )
        return self._client

    def put_object(
        self,
        *,
        object_key: str,
        data: bytes,
        content_type: str,
        metadata: dict[str, str] | None = None,
    ) -> StoredObject:
        validate_object_key(object_key)
        validate_object_size(data, max_bytes=self._max_bytes)
        validate_content_type(content_type)
        digest = hashlib.sha256(data).hexdigest()
        # Server-side encryption: the bucket is private, but private plus
        # encrypted at rest means a leaked object is still not readable, and a
        # misconfigured bucket policy does not turn into a disclosure.
        arguments: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": object_key,
            "Body": data,
            "ContentType": content_type,
            "ServerSideEncryption": "AES256",
        }
        if metadata:
            arguments["Metadata"] = {key: str(value) for key, value in metadata.items()}

        try:
            response = self.client.put_object(**arguments)
        except (BotoCoreError, ClientError) as exc:
            raise StorageError("The file could not be stored.") from exc

        logger.info(
            "storage.object_stored",
            extra={"bucket": self._bucket, "object_key": object_key, "size": len(data)},
        )
        etag = response.get("ETag")
        return StoredObject(
            bucket=self._bucket,
            object_key=object_key,
            size_bytes=len(data),
            sha256=digest,
            etag=etag.strip('"') if isinstance(etag, str) else None,
        )

    def get_object(self, *, object_key: str) -> bytes:
        validate_object_key(object_key)
        try:
            response = self.client.get_object(Bucket=self._bucket, Key=object_key)
            body = response["Body"].read()
        except ClientError as exc:
            if _is_missing_object(exc):
                raise NotFoundError("That file is no longer available.") from exc
            raise StorageError("The file could not be read.") from exc
        except BotoCoreError as exc:
            raise StorageError("The file could not be read.") from exc

        if not isinstance(body, bytes):  # pragma: no cover - botocore always returns bytes
            raise StorageError("The file could not be read.")
        return body

    def delete_object(self, *, object_key: str) -> None:
        validate_object_key(object_key)
        try:
            self.client.delete_object(Bucket=self._bucket, Key=object_key)
        except (BotoCoreError, ClientError) as exc:
            raise StorageError("The file could not be deleted.") from exc
        logger.info(
            "storage.object_deleted",
            extra={"bucket": self._bucket, "object_key": object_key},
        )

    def object_exists(self, *, object_key: str) -> bool:
        validate_object_key(object_key)
        try:
            self.client.head_object(Bucket=self._bucket, Key=object_key)
        except ClientError as exc:
            if _is_missing_object(exc):
                return False
            raise StorageError("The file could not be inspected.") from exc
        except BotoCoreError as exc:
            raise StorageError("The file could not be inspected.") from exc
        return True

    def create_download_url(
        self,
        *,
        object_key: str,
        expires_in: int | None = None,
        download_filename: str | None = None,
        content_type: str | None = None,
    ) -> str:
        validate_object_key(object_key)
        ttl = _clamp_ttl(expires_in, self._url_ttl_seconds)
        response_content_type = content_type or SAFE_FALLBACK_CONTENT_TYPE

        parameters: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": object_key,
            # Pin the type the object was stored as. Without it the response
            # carries whatever `Content-Type` the object metadata holds, and if
            # that is ever wrong the browser is free to sniff the bytes and
            # decide for itself - which is how a stored document becomes
            # script executed in our origin. Setting it explicitly means the
            # decision was made by the sniffing code that already validated the
            # bytes, not by the browser.
            "ResponseContentType": response_content_type,
            # Never let the browser render an upload inline. Inline rendering is
            # a rendering decision about attacker-influenced bytes; `attachment`
            # removes the decision.
            "ResponseContentDisposition": "attachment",
        }
        if download_filename:
            # The caller is expected to pass an already-escaped disposition
            # value. Anything smuggled in here would only affect how the file is
            # saved, not what is served, because `ResponseContentType` and the
            # bucket ACL are independent of it.
            parameters["ResponseContentDisposition"] = download_filename

        try:
            return str(
                self.client.generate_presigned_url(
                    "get_object",
                    Params=parameters,
                    ExpiresIn=ttl,
                )
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageError("The file could not be made available.") from exc


# --------------------------------------------------------------------------- #
# Key and size validation                                                    #
# --------------------------------------------------------------------------- #
def validate_object_key(object_key: str) -> str:
    """Return ``object_key`` if it is safe to hand to a storage backend. Args: object_key: The key t..."""
    if not object_key:
        raise ValidationError("A storage object key is required.")
    if len(object_key) > MAX_OBJECT_KEY_LENGTH:
        raise ValidationError("That storage object key is too long.")
    if ".." in object_key:
        raise ValidationError("Invalid storage object key.")
    if object_key.startswith("/") or object_key.endswith("/") or "//" in object_key:
        raise ValidationError("Invalid storage object key.")
    if "\\" in object_key:
        raise ValidationError("Invalid storage object key.")
    if _CONTROL_CHARACTERS.search(object_key):
        raise ValidationError("Invalid storage object key.")
    if _SCHEME_LIKE_PREFIX.match(object_key):
        raise ValidationError("Invalid storage object key.")
    return object_key


def validate_object_size(data: bytes, *, max_bytes: int) -> int:
    """Return the length of ``data`` if it is within the backend's ceiling. Raises: ValidationError:..."""
    size = len(data)
    if size == 0:
        raise ValidationError("The uploaded file is empty.")
    if size > max_bytes:
        raise FileTooLargeError("That file is too large.")
    return size


def validate_content_type(content_type: str) -> str:
    """Return ``content_type`` if it is safe to record as an object's type. Raises: ValidationError:..."""
    if not content_type or not content_type.strip():
        raise ValidationError("A content type is required to store a file.")
    if len(content_type) > MAX_CONTENT_TYPE_LENGTH:
        raise ValidationError("That content type is too long.")
    if _CONTROL_CHARACTERS.search(content_type) or ";" in content_type:
        raise ValidationError("Invalid content type.")
    return content_type.strip().lower()


def _clamp_ttl(expires_in: int | None, maximum: int) -> int:
    """Bound a requested URL lifetime. Raises: ValidationError: ``expires_in`` is not a positive int..."""
    if expires_in is None:
        return maximum
    if expires_in <= 0:
        raise ValidationError("A signed URL must have a positive lifetime.")
    return min(expires_in, maximum)


def _is_missing_object(exc: ClientError) -> bool:
    """Whether a botocore error means "no such object"."""
    error = exc.response.get("Error", {}) if exc.response else {}
    code = str(error.get("Code", ""))
    status = str(
        exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "") if exc.response else ""
    )
    return code in _CLIENT_ERROR_CODES or status in {"403", "404"}


def _client_config(use_path_style: bool) -> Config:
    """Build the botocore config, disabling retries that outlive a request."""
    return Config(
        signature_version="s3v4",
        s3={"addressing_style": "path" if use_path_style else "auto"},
        retries={"max_attempts": 3, "mode": "standard"},
        connect_timeout=5,
        read_timeout=30,
    )


# --------------------------------------------------------------------------- #
# Factory                                                                    #
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def get_storage() -> Storage:
    """Return the process-wide :class:`Storage` for the configured backend. Raises: ServiceUnavailab..."""
    settings = get_settings()
    if settings.storage_backend == "s3":
        return S3Storage(
            bucket=settings.storage_bucket,
            access_key_id=settings.storage_access_key.get_secret_value(),
            secret_access_key=settings.storage_secret_key.get_secret_value(),
            region=settings.storage_region,
            endpoint_url=settings.storage_endpoint,
            use_path_style=settings.storage_use_path_style,
            max_bytes=settings.max_upload_size_bytes,
            url_ttl_seconds=settings.signed_url_ttl_seconds,
        )
    if settings.is_production:
        raise ServiceUnavailableError(
            "Refusing to start with in-memory storage in production. Set "
            "STORAGE_BACKEND=s3 and configure the bucket and credentials; every "
            "uploaded document would be lost on restart."
        )
    return InMemoryStorage(
        max_bytes=settings.max_upload_size_bytes,
        url_ttl_seconds=settings.signed_url_ttl_seconds,
    )


def reset_storage() -> None:
    """Drop the cached backend so the next call rebuilds it from settings."""
    get_storage.cache_clear()


__all__ = [
    "InMemoryStorage",
    "S3Storage",
    "Storage",
    "StorageError",
    "StoredObject",
    "get_storage",
    "reset_storage",
    "validate_object_key",
]
