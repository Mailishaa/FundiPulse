"""Decide what an uploaded payload actually is, before anything is stored."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Final
import unicodedata
from urllib.parse import quote
import uuid

from app.core.config import ALLOWED_UPLOAD_EXTENSIONS, ALLOWED_UPLOAD_MIME_TYPES, get_settings
from app.core.constants import FilePurpose
from app.core.exceptions import (
    FileTooLargeError,
    UnsupportedFileTypeError,
    ValidationError,
)
from app.core.security import generate_opaque_token

# --------------------------------------------------------------------------- #
# Type detection                                                             #
# --------------------------------------------------------------------------- #
#: Canonical extension per supported type. Every value must appear in
#: ``ALLOWED_UPLOAD_EXTENSIONS``; :func:`extension_for_content_type` verifies
#: that at runtime so the two allowlists cannot silently drift apart.
_CANONICAL_EXTENSION_BY_TYPE: Final[dict[str, str]] = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "application/pdf": ".pdf",
}

#: Every extension a client may legitimately name for a given sniffed type.
#: ``.jpeg`` is a synonym for ``.jpg``; the canonical form is still what goes
#: into the object key, so the key extension never depends on what the client
#: called the file.
_EXTENSIONS_BY_TYPE: Final[dict[str, frozenset[str]]] = {
    "image/jpeg": frozenset({".jpg", ".jpeg"}),
    "image/png": frozenset({".png"}),
    "image/webp": frozenset({".webp"}),
    "application/pdf": frozenset({".pdf"}),
}

#: Matches the leading bytes of each supported format.
_JPEG_MAGIC: Final[bytes] = b"\xff\xd8\xff"
_PNG_MAGIC: Final[bytes] = b"\x89PNG\r\n\x1a\n"
_PDF_MAGIC: Final[bytes] = b"%PDF-"
#: WebP is a RIFF container: ``RIFF`` + 4-byte length + ``WEBP``. The size field
#: is skipped because it varies; the form identifier at offset 8 is the part
#: that distinguishes WebP from WAV/AVI.
_RIFF_MAGIC: Final[bytes] = b"RIFF"
_WEBP_FORM: Final[bytes] = b"WEBP"

#: Mirrors ``CHECK (size_bytes > 0 AND size_bytes <= 26214400)`` on ``files``.
#: The database is the real ceiling; this constant exists so the application
#: refuses an oversized payload before writing bytes, instead of accepting them
#: and then failing at insert time with a raw constraint violation.
HARD_MAX_UPLOAD_BYTES: Final[int] = 25 * 1024 * 1024

#: Display name used when nothing usable survives sanitisation. Neutral by
#: design: it must not imply a file type or reveal anything about the upload.
DEFAULT_DISPLAY_FILENAME: Final[str] = "upload"

#: Byte length of the random component of an object key. 32 bytes = 256 bits,
#: so keys are not guessable even if one leaks through a log line.
_OBJECT_KEY_TOKEN_BYTES: Final[int] = 32

# --------------------------------------------------------------------------- #
# Filename sanitisation                                                      #
# --------------------------------------------------------------------------- #
_WHITESPACE_RUN: Final[re.Pattern[str]] = re.compile(r"\s+")
_DOT_RUN: Final[re.Pattern[str]] = re.compile(r"\.{2,}")
_DISALLOWED_FILENAME_CHARACTERS: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9 ._\-()\[\]]")

#: Unicode general categories that never survive into a display name.
#: ``Cf`` is the important one - it covers bidirectional overrides such as
#: U+202E and zero-width joiners, which is how a file called ``photo<RLO>gnp.exe``
#: renders as ``photoexe.png`` on a screen and as the truth on disk.
_UNSAFE_UNICODE_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"Cc", "Cf", "Cn", "Co", "Cs", "Zl", "Zp"}
)

#: Characters permitted in a server-generated object key. Deliberately narrow:
#: it is the alphabet of a UUID, a CSPRNG token and a controlled vocabulary, so
#: anything outside it means the key did not come from
#: :func:`generate_object_key`.
_SAFE_KEY_CHARACTERS: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._/-]+$")

#: Longest object key accepted anywhere. Matches ``files.object_key`` so a key
#: that this module can produce is always storable.
MAX_OBJECT_KEY_LENGTH: Final[int] = 512


def detect_content_type(data: bytes) -> str | None:
    """Return the type implied by the payload's magic number, or ``None``. Args: data: The raw uploa..."""
    if data.startswith(_JPEG_MAGIC):
        return "image/jpeg"
    if data.startswith(_PNG_MAGIC):
        return "image/png"
    if data[: len(_RIFF_MAGIC)] == _RIFF_MAGIC and data[8:12] == _WEBP_FORM:
        return "image/webp"
    if data.startswith(_PDF_MAGIC):
        return "application/pdf"
    return None


def _normalise_content_type(content_type: str) -> str:
    """Strip parameters and case from a content type."""
    return content_type.split(";", 1)[0].strip().lower()


def extension_for_content_type(content_type: str) -> str:
    """Return the canonical extension for a *validated* content type. Args: content_type: A type tha..."""
    normalised = _normalise_content_type(content_type)
    extension = _CANONICAL_EXTENSION_BY_TYPE.get(normalised)
    if normalised not in ALLOWED_UPLOAD_MIME_TYPES or extension is None:
        raise UnsupportedFileTypeError("That file type is not accepted.")
    if extension not in ALLOWED_UPLOAD_EXTENSIONS:
        # Configuration drift: a supported type has no allowlisted extension.
        # Failing closed here is the safe direction; the fix is in config.py.
        raise UnsupportedFileTypeError("That file type is not accepted.")
    return extension


def _assert_generated_key_is_safe(object_key: str) -> None:
    """Assert a generated key has the exact shape this module promises."""
    if not _SAFE_KEY_CHARACTERS.match(object_key):
        raise ValidationError("Refusing to build an object key with unsafe characters.")
    if ".." in object_key:
        raise ValidationError("Refusing to build an object key containing '..'.")
    if object_key.count("/") != 2 or object_key.startswith("/") or object_key.endswith("/"):
        raise ValidationError("Object keys must be namespaced as <purpose>/<owner>/<token>.")


def generate_object_key(*, purpose: str, content_type: str, owner_id: uuid.UUID) -> str:
    """Return a storage key of the form ``<purpose>/<owner_uuid>/<token>.<ext>``. Args: purpose: A :..."""
    try:
        validated_purpose = FilePurpose(purpose)
    except ValueError as exc:
        raise ValidationError("Unknown file purpose.") from exc

    extension = extension_for_content_type(content_type)
    # `generate_opaque_token` is `secrets.token_urlsafe`, i.e. a CSPRNG. The
    # url-safe alphabet is a subset of the characters `_SAFE_KEY_CHARACTERS`
    # permits, so the token cannot introduce a separator.
    token = generate_opaque_token(_OBJECT_KEY_TOKEN_BYTES)
    object_key = f"{validated_purpose.value}/{owner_id}/{token}{extension}"
    _assert_generated_key_is_safe(object_key)
    return object_key


def sanitise_display_filename(
    filename: str | None,
    *,
    max_length: int = 255,
) -> str:
    """Return a filename safe to *display* - never safe to *use as a path*. Args: filename: The raw ..."""
    if max_length <= 0:
        raise ValidationError("max_length must be positive.")
    if not filename:
        return DEFAULT_DISPLAY_FILENAME

    # Take the last path component *before* anything else: the directory part of
    # a traversal attempt is the part that must not survive, whatever else
    # happens to it afterwards.
    candidate = filename.replace("\\", "/").rsplit("/", 1)[-1]
    candidate = _sanitise_filename_characters(candidate)
    candidate = _WHITESPACE_RUN.sub(" ", candidate).strip()
    # Runs of dots collapse to one, so ``..`` cannot appear anywhere in the
    # result. It is harmless here because the value is never resolved on a
    # filesystem, but a consumer downstream that does join it against a directory
    # deserves not to be handed a traversal sequence by accident.
    candidate = _DOT_RUN.sub(".", candidate).strip()
    # Leading dots are stripped as well: a name of only dots is not a name, and
    # a leading dot would otherwise render as a hidden file.
    candidate = candidate.lstrip(".").strip()

    if candidate:
        candidate = _truncate_preserving_extension(candidate, max_length)
    return candidate or DEFAULT_DISPLAY_FILENAME


def _truncate_preserving_extension(name: str, max_length: int) -> str:
    """Shorten ``name`` to ``max_length``, keeping the extension if there is one."""
    if len(name) <= max_length:
        return name
    stem, dot, extension = name.rpartition(".")
    if not dot or len(extension) >= 16 or len(extension) >= max_length:
        return name[:max_length].strip()
    keep = max(max_length - len(extension) - 1, 1)
    return f"{stem[:keep].strip()}.{extension}"


def content_disposition_value(filename: str | None) -> str:
    """Return a complete, injection-proof ``Content-Disposition`` header value. Args: filename: The ..."""
    safe = sanitise_display_filename(filename)
    # RFC 6266 quoted-string escaping. Unreachable for a sanitised name, and kept
    # deliberately: if the sanitiser is ever widened, this still holds.
    quoted = _ascii_fallback(safe).replace("\\", "\\\\").replace('"', '\\"')
    encoded = quote(safe, safe="")
    value = f"attachment; filename=\"{quoted}\"; filename*=UTF-8''{encoded}"

    if "\r" in value or "\n" in value:  # pragma: no cover - unreachable by construction
        raise ValidationError(
            "Refusing to emit a Content-Disposition header with control characters."
        )
    return value


def _sanitise_filename_characters(name: str) -> str:
    """Drop characters that must never reach a display name or a header."""
    kept: list[str] = []
    for character in name:
        if unicodedata.category(character) in _UNSAFE_UNICODE_CATEGORIES:
            continue
        if not character.isascii() or character.isalnum() or character in " ._-()[]":
            kept.append(character)
    return "".join(kept)


def _ascii_fallback(name: str) -> str:
    """Return an ASCII-only version of ``name`` for legacy header clients."""
    decomposed = unicodedata.normalize("NFKD", name)
    stripped = decomposed.encode("ascii", "ignore").decode("ascii")
    cleaned = _DISALLOWED_FILENAME_CHARACTERS.sub("", stripped)
    return _WHITESPACE_RUN.sub(" ", cleaned).strip() or DEFAULT_DISPLAY_FILENAME


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def validate_upload_size(size: int, *, max_bytes: int | None = None) -> None:
    """Raise unless ``size`` is a plausible, permitted upload length. Args: size: Length of the payl..."""
    ceiling = get_settings().max_upload_size_bytes if max_bytes is None else max_bytes
    if ceiling <= 0:
        raise ValidationError("The maximum upload size must be positive.")
    if size <= 0:
        raise ValidationError("The uploaded file is empty.")
    if size > min(ceiling, HARD_MAX_UPLOAD_BYTES):
        raise FileTooLargeError(
            f"That file is too large. The maximum accepted size is "
            f"{min(ceiling, HARD_MAX_UPLOAD_BYTES)} bytes."
        )


# --------------------------------------------------------------------------- #
# The single entry point used by the upload route                             #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class UploadInspection:
    """Everything the upload path is allowed to learn about a payload."""

    content_type: str
    """The sniffed type. Never the client's claim."""

    size_bytes: int
    """Length of the payload, already checked against the ceiling."""

    sha256: str
    """Hex digest for integrity checks and duplicate detection."""

    extension: str
    """Canonical extension, including the dot. The only extension allowed in a key."""

    safe_filename: str
    """Display-only name. Never a path, never a raw header value."""

    @property
    def object_key_suffix(self) -> str:
        """Alias for :attr:`extension`, named for how it is used in a key."""
        return self.extension


def inspect_upload(
    data: bytes,
    *,
    declared_content_type: str | None,
    declared_filename: str | None,
    max_bytes: int,
) -> UploadInspection:
    """Validate an upload end to end and return the values to persist. Args: data: Raw uploaded byte..."""
    if not data:
        raise ValidationError("The uploaded file is empty.")
    validate_upload_size(len(data), max_bytes=max_bytes)

    sniffed = detect_content_type(data)
    if sniffed is None:
        raise UnsupportedFileTypeError("That file type is not accepted.")
    extension = extension_for_content_type(sniffed)

    if declared_content_type and _normalise_content_type(declared_content_type) != sniffed:
        raise UnsupportedFileTypeError("The uploaded file does not match its declared type.")

    if declared_filename:
        _check_declared_extension(declared_filename, sniffed)

    return UploadInspection(
        content_type=sniffed,
        size_bytes=len(data),
        sha256=sha256_hex(data),
        extension=extension,
        safe_filename=sanitise_display_filename(declared_filename),
    )


def _check_declared_extension(declared_filename: str, sniffed: str) -> None:
    """Reject an uploaded filename whose extension contradicts the signature."""
    base = declared_filename.replace("\\", "/").rsplit("/", 1)[-1]
    _, dot, suffix = base.rpartition(".")
    if not dot or not suffix:
        return
    declared_extension = f".{suffix.lower()}"
    if declared_extension not in ALLOWED_UPLOAD_EXTENSIONS:
        raise UnsupportedFileTypeError("That file type is not accepted.")
    if declared_extension not in _EXTENSIONS_BY_TYPE[sniffed]:
        raise UnsupportedFileTypeError("The uploaded file does not match its filename extension.")
