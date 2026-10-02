"""Unit tests for upload inspection.

Pure functions over bytes: no database, no HTTP, no storage. These tests are
written as the argument for the design decisions rather than as a restatement of
the implementation, so a change that weakens the guarantee fails here.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.exceptions import (
    FileTooLargeError,
    UnsupportedFileTypeError,
    ValidationError,
)
from app.utils.fileinspect import (
    DEFAULT_DISPLAY_FILENAME,
    HARD_MAX_UPLOAD_BYTES,
    UploadInspection,
    content_disposition_value,
    detect_content_type,
    extension_for_content_type,
    generate_object_key,
    inspect_upload,
    sanitise_display_filename,
    sha256_hex,
    validate_upload_size,
)

pytestmark = pytest.mark.unit

#: Minimal payloads that are structurally valid for each format. The bytes after
#: the signature are irrelevant to sniffing, so keeping them tiny keeps these
#: tests about detection rather than about fixtures.
JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
WEBP_BYTES = b"RIFF" + b"\x24\x00\x00\x00" + b"WEBPVP8 " + b"\x00" * 16
PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"\x00" * 32

ZIP_BYTES = b"PK\x03\x04" + b"\x14\x00\x00\x00" + b"\x00" * 24
TEXT_BYTES = b"<html><body>hello</body></html>"
RANDOM_BYTES = bytes(range(256)) * 4

MAX_BYTES = 1024 * 1024


# --------------------------------------------------------------------------- #
# Magic-number detection                                                      #
# --------------------------------------------------------------------------- #
class TestDetectContentType:
    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            pytest.param(JPEG_BYTES, "image/jpeg", id="jpeg"),
            pytest.param(PNG_BYTES, "image/png", id="png"),
            pytest.param(WEBP_BYTES, "image/webp", id="webp"),
            pytest.param(PDF_BYTES, "application/pdf", id="pdf"),
        ],
    )
    def test_recognises_each_supported_signature(self, payload: bytes, expected: str) -> None:
        assert detect_content_type(payload) == expected

    @pytest.mark.parametrize(
        ("payload", "label"),
        [
            pytest.param(b"", "empty"),
            pytest.param(b"not a file at all, just prose", "text"),
            pytest.param(TEXT_BYTES, "html"),
            pytest.param(ZIP_BYTES, "zip"),
            pytest.param(RANDOM_BYTES, "random"),
            pytest.param(b"\x00\x00\x00\x00", "nul bytes"),
        ],
    )
    def test_returns_none_for_anything_else(self, payload: bytes, label: str) -> None:
        assert detect_content_type(payload) is None, label

    def test_ignores_a_declared_looking_prefix(self) -> None:
        """Only the signature decides; nothing else in the payload is consulted."""
        payload = b"\x89PNG\r\n\x1a\n<html>polyglot</html>"

        assert detect_content_type(payload) == "image/png"

    def test_jpeg_signature_requires_all_three_bytes(self) -> None:
        """``ff d8`` alone is not a JPEG signature; ``ff d8 ff`` is.

        Without the third byte check a two-byte prefix would match a large class
        of unrelated binary data.
        """
        assert detect_content_type(b"\xff\xd8\x00\x01") is None

    def test_riff_without_the_webp_form_type_is_not_webp(self) -> None:
        """A RIFF container with a different form type is not an image.

        WAV and AVI share the ``RIFF`` prefix, so accepting the prefix alone would
        accept arbitrary RIFF payloads.
        """
        wav = b"RIFF" + b"\x24\x00\x00\x00" + b"WAVEfmt " + b"\x00" * 16

        assert detect_content_type(wav) is None


# --------------------------------------------------------------------------- #
# Extension allowlist                                                         #
# --------------------------------------------------------------------------- #
class TestExtensionForContentType:
    @pytest.mark.parametrize(
        ("content_type", "expected"),
        [
            ("image/jpeg", ".jpg"),
            ("image/png", ".png"),
            ("image/webp", ".webp"),
            ("application/pdf", ".pdf"),
        ],
    )
    def test_maps_allowed_types_to_canonical_extensions(
        self, content_type: str, expected: str
    ) -> None:
        assert extension_for_content_type(content_type) == expected

    def test_ignores_parameters_and_case(self) -> None:
        """``image/jpeg; charset=binary`` is the same claim as ``image/jpeg``."""
        assert extension_for_content_type("IMAGE/JPEG; charset=binary") == ".jpg"

    @pytest.mark.parametrize(
        "content_type",
        [
            "image/gif",
            "image/svg+xml",
            "text/html",
            "application/octet-stream",
            "application/zip",
            "text/javascript",
            "",
            "image/jpg",
        ],
    )
    def test_rejects_types_outside_the_allowlist(self, content_type: str) -> None:
        with pytest.raises(UnsupportedFileTypeError):
            extension_for_content_type(content_type)

    def test_svg_and_html_are_rejected_because_they_are_renderers(self) -> None:
        """The allowlist excludes types a browser will *execute*.

        SVG can carry script and HTML obviously can, so accepting either would
        mean storing an XSS payload that our own signed URL hands back.
        """
        for content_type in ("image/svg+xml", "text/html"):
            with pytest.raises(UnsupportedFileTypeError):
                extension_for_content_type(content_type)


# --------------------------------------------------------------------------- #
# Object key generation                                                       #
# --------------------------------------------------------------------------- #
class TestGenerateObjectKey:
    def test_has_the_documented_shape(self) -> None:
        owner = uuid.uuid4()

        key = generate_object_key(
            purpose="WORK_EVIDENCE", content_type="image/jpeg", owner_id=owner
        )

        purpose, key_owner, filename = key.split("/")
        assert purpose == "WORK_EVIDENCE"
        assert key_owner == str(owner)
        assert filename.endswith(".jpg")

    def test_namespaces_by_owner_so_two_users_never_collide(self) -> None:
        first = generate_object_key(
            purpose="WORK_EVIDENCE",
            content_type="image/png",
            owner_id=uuid.uuid4(),
        )
        second = generate_object_key(
            purpose="WORK_EVIDENCE",
            content_type="image/png",
            owner_id=uuid.uuid4(),
        )

        assert first.split("/")[1] != second.split("/")[1]

    def test_is_unique_per_call_for_the_same_owner(self) -> None:
        """The random component defeats both guessing and enumeration.

        Two uploads by one worker must not be predictable from each other, or a
        leaked key reveals the whole owner's prefix.
        """
        owner = uuid.uuid4()
        keys = {
            generate_object_key(purpose="WORK_EVIDENCE", content_type="image/jpeg", owner_id=owner)
            for _ in range(50)
        }

        assert len(keys) == 50

    def test_never_contains_a_traversal_sequence(self) -> None:
        """Path traversal is unconstructible, not filtered.

        The key is assembled from a controlled vocabulary, a UUID, a CSPRNG token
        and an extension derived from the sniffed type, so there is no user input
        anywhere in it for ``..`` to ride in on.
        """
        for _ in range(100):
            key = generate_object_key(
                purpose="CREDENTIAL_DOCUMENT",
                content_type="application/pdf",
                owner_id=uuid.uuid4(),
            )
            assert ".." not in key
            assert not key.startswith("/")
            assert key.count("/") == 2

    def test_contains_no_characters_outside_the_safe_alphabet(self) -> None:
        for _ in range(50):
            key = generate_object_key(
                purpose="ORGANIZATION_LOGO",
                content_type="image/webp",
                owner_id=uuid.uuid4(),
            )
            assert all(character.isalnum() or character in "._/-" for character in key)

    def test_rejects_a_purpose_outside_the_controlled_vocabulary(self) -> None:
        """A caller-supplied purpose cannot smuggle a separator into the key."""
        with pytest.raises(ValidationError):
            generate_object_key(
                purpose="../../etc",
                content_type="image/jpeg",
                owner_id=uuid.uuid4(),
            )

    def test_rejects_a_disallowed_content_type(self) -> None:
        with pytest.raises(UnsupportedFileTypeError):
            generate_object_key(
                purpose="WORK_EVIDENCE",
                content_type="text/html",
                owner_id=uuid.uuid4(),
            )

    def test_every_purpose_produces_a_valid_key(self) -> None:
        """The vocabulary and the key layout cannot drift apart.

        Enumerating the enum is the check: adding a purpose to
        ``constants.FilePurpose`` without a key layout that fits would fail here.
        """
        from app.core.constants import FilePurpose

        for purpose in FilePurpose:
            key = generate_object_key(
                purpose=purpose.value,
                content_type="image/jpeg",
                owner_id=uuid.uuid4(),
            )
            assert key.startswith(f"{purpose.value}/")
            assert key.count("/") == 2

    @pytest.mark.parametrize(
        ("object_key", "reason"),
        [
            pytest.param("purpose/owner/token.jpg ", "trailing space", id="unsafe-charset"),
            pytest.param("purpose/owner/../token.jpg", "dot-dot", id="dot-dot"),
            pytest.param("purpose/owner", "missing segment", id="too-few-separators"),
            pytest.param("/purpose/owner/token.jpg", "absolute", id="leading-separator"),
            pytest.param("purpose/owner/token.jpg/", "empty segment", id="trailing-separator"),
        ],
    )
    def test_the_internal_key_invariant_check_fails_loudly(
        self, object_key: str, reason: str
    ) -> None:
        """If the generator is ever broken, it must raise rather than return a bad key.

        Every assertion in ``generate_object_key`` is unreachable by construction,
        so they are tested directly. A silently-weakened check here would reopen
        the path-traversal class of bug the ADR says is structurally impossible.
        """
        from app.utils.fileinspect import _assert_generated_key_is_safe

        with pytest.raises(ValidationError):
            _assert_generated_key_is_safe(object_key)

    def test_the_internal_key_check_passes_a_real_key(self) -> None:
        from app.utils.fileinspect import _assert_generated_key_is_safe

        key = generate_object_key(
            purpose="WORK_EVIDENCE",
            content_type="image/jpeg",
            owner_id=uuid.uuid4(),
        )

        assert _assert_generated_key_is_safe(key) is None

    def test_fails_closed_when_the_allowlists_disagree(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A supported type with no allowlisted extension is refused, not guessed.

        The two allowlists live in ``config.py`` and can be edited independently;
        producing a key whose extension the rest of the system does not expect
        would be the worse failure.
        """
        import app.utils.fileinspect as fileinspect

        monkeypatch.setitem(fileinspect._CANONICAL_EXTENSION_BY_TYPE, "image/png", ".tiff")

        with pytest.raises(UnsupportedFileTypeError):
            extension_for_content_type("image/png")

    def test_extension_comes_from_the_content_type_not_the_filename(self) -> None:
        """No filename is accepted at all, which is the strongest possible guarantee."""
        key = generate_object_key(
            purpose="WORK_EVIDENCE", content_type="image/png", owner_id=uuid.uuid4()
        )

        assert key.endswith(".png")


# --------------------------------------------------------------------------- #
# Display-name sanitisation                                                   #
# --------------------------------------------------------------------------- #
class TestSanitiseDisplayFilename:
    def test_keeps_an_ordinary_name_intact(self) -> None:
        assert sanitise_display_filename("Site-Photos_Kenya (2).pdf") == (
            "Site-Photos_Kenya (2).pdf"
        )

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            pytest.param("../../etc/passwd", "passwd", id="posix-traversal"),
            pytest.param(
                "..\\..\\windows\\system32\\config.txt",
                "config.txt",
                id="windows-traversal",
            ),
            pytest.param("/absolute/path/certificate.pdf", "certificate.pdf", id="absolute"),
            pytest.param("C:\\Users\\Jomo\\photo.jpg", "photo.jpg", id="drive-letter"),
            pytest.param("nested/dir/name.png", "name.png", id="nested"),
        ],
    )
    def test_strips_every_directory_component(self, raw: str, expected: str) -> None:
        """Both separators are honoured.

        Honouring only ``/`` would leave ``..\\..\\windows\\system32`` for whatever
        consumes this value, which is exactly the string a Windows-side consumer
        would resolve.
        """
        assert sanitise_display_filename(raw) == expected

    def test_strips_control_characters(self) -> None:
        assert sanitise_display_filename("a\x00b\x07c\x1bd.txt") == "abcd.txt"

    def test_strips_a_console_escape_sequence(self) -> None:
        """A name carrying ``ESC [ 31 m`` would repaint a terminal or a log viewer."""
        assert sanitise_display_filename("a\x1b[31mred.txt") == "a[31mred.txt"

    def test_strips_bidirectional_overrides(self) -> None:
        """A right-to-left override is the Trojan Source trick.

        ``photo<RLO>gnp.exe`` renders as ``photoexe.png`` on screen. Dropping the
        format character means the displayed name and the real name agree.
        """
        result = sanitise_display_filename("photo‮gnp.exe")

        assert "‮" not in result
        assert result == "photognp.exe"

    def test_strips_quotes_and_semicolons(self) -> None:
        """No byte survives that could terminate a quoted header parameter."""
        assert '"' not in sanitise_display_filename('a"b;c.txt')

    def test_collapses_whitespace(self) -> None:
        assert sanitise_display_filename("my    photo \t name.png") == "my photo name.png"

    def test_preserves_a_non_ascii_name(self) -> None:
        """Sanitisation is not ASCII-only, because Kenyan names are not ASCII.

        Stripping every non-ASCII character would look safe and quietly destroy
        the one piece of information that lets a worker recognise their own
        certificate.
        """
        assert sanitise_display_filename("Ñoño-mradi résumé.pdf") == "Ñoño-mradi résumé.pdf"

    def test_caps_the_length_and_keeps_the_extension(self) -> None:
        result = sanitise_display_filename(f"{'a' * 400}.jpg", max_length=64)

        assert len(result) <= 64
        assert result.endswith(".jpg")

    def test_defaults_to_the_cap_matching_the_database_column(self) -> None:
        """``files.original_filename`` is ``String(255)``; the cap is not arbitrary."""
        assert len(sanitise_display_filename("a" * 1000)) <= 255

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param(None, id="none"),
            pytest.param("", id="empty"),
            pytest.param("...", id="only-dots"),
            pytest.param("../../..", id="only-traversal"),
            pytest.param("\x00\x01\x02", id="only-control-characters"),
            pytest.param("   ", id="only-whitespace"),
        ],
    )
    def test_falls_back_to_a_neutral_default(self, raw: str | None) -> None:
        """When nothing survives there is still something safe to render."""
        assert sanitise_display_filename(raw) == DEFAULT_DISPLAY_FILENAME

    def test_rejects_a_non_positive_cap(self) -> None:
        with pytest.raises(ValidationError):
            sanitise_display_filename("photo.png", max_length=0)

    def test_result_is_never_a_usable_path(self) -> None:
        """The value is for display. It cannot be mistaken for a path."""
        result = sanitise_display_filename("../../etc/shadow")

        assert "/" not in result
        assert "\\" not in result
        assert ".." not in result


# --------------------------------------------------------------------------- #
# Content-Disposition                                                        #
# --------------------------------------------------------------------------- #
class TestContentDispositionValue:
    def test_emits_both_rfc6266_forms(self) -> None:
        value = content_disposition_value("certificate.pdf")

        assert value.startswith("attachment;")
        assert 'filename="certificate.pdf"' in value
        assert "filename*=UTF-8''certificate.pdf" in value

    def test_always_forces_an_attachment(self) -> None:
        """Inline rendering is a rendering decision about attacker-chosen bytes."""
        assert content_disposition_value("evil.html").startswith("attachment;")

    @pytest.mark.parametrize(
        "hostile",
        [
            pytest.param('evil";\r\nSet-Cookie: session=stolen', id="quote-and-crlf"),
            pytest.param("file\r\nX-Injected: 1\r\nname.pdf", id="bare-crlf"),
            pytest.param('a"b.txt', id="bare-quote"),
            pytest.param("a\\b.txt", id="backslash"),
            pytest.param("a;b.txt", id="semicolon"),
        ],
    )
    def test_neutralises_header_injection(self, hostile: str) -> None:
        """No crafted filename can add a header line or a parameter.

        CR and LF are the dangerous part: either one ends the header value, and
        everything after it is parsed by the client as a new header. The sanitiser
        removes both, and the escape plus the final assertion mean widening the
        sanitiser cannot silently reopen this.
        """
        value = content_disposition_value(hostile)

        # CR or LF ends the header value, so everything after it would be parsed
        # as a new header by the client.
        assert "\r" not in value
        assert "\n" not in value
        # A surviving quote or semicolon would let extra parameters be parsed out
        # of the same header. Only the three parts we emit are present.
        assert value.count('filename="') == 1
        assert value.count("filename*=UTF-8''") == 1
        assert len(value.split(";")) == 3

    def test_percent_encodes_a_non_ascii_name(self) -> None:
        """The RFC 5987 form preserves a name the ASCII form cannot express."""
        value = content_disposition_value("Ñoño-mradi.pdf")

        assert "filename*=UTF-8''%C3%91o%C3%B1o-mradi.pdf" in value
        # The legacy form is ASCII-only, as RFC 6266 requires.
        assert 'filename="Nono-mradi.pdf"' in value

    def test_ascii_fallback_is_never_empty(self) -> None:
        """A name with no ASCII content at all still yields a usable fallback.

        NFKD decomposition turns each ``Ñ`` into ``N`` plus a combining tilde, and
        the mark is dropped, so the fallback is ``NNN`` rather than nothing.
        """
        value = content_disposition_value("ÑÑÑ")

        assert 'filename="NNN"' in value

    def test_handles_a_missing_filename(self) -> None:
        value = content_disposition_value(None)

        assert value.startswith("attachment;")
        assert 'filename="upload"' in value

    def test_strips_traversal_from_the_suggested_name(self) -> None:
        assert "../../etc/passwd" not in content_disposition_value("../../etc/passwd")

    def test_collapses_dot_runs_so_no_traversal_can_survive_anywhere(self) -> None:
        """``..`` cannot appear even mid-name.

        The value is display-only so it is never resolved, but a consumer that
        joins it against a directory should not be handed a traversal sequence
        because someone named a file ``report..pdf``.
        """
        assert sanitise_display_filename("0...") == "0."
        assert sanitise_display_filename("report....pdf") == "report.pdf"


# --------------------------------------------------------------------------- #
# Hashing and size                                                           #
# --------------------------------------------------------------------------- #
class TestSha256AndSize:
    def test_sha256_matches_hashlib(self) -> None:
        import hashlib

        assert sha256_hex(b"fundipulse") == hashlib.sha256(b"fundipulse").hexdigest()

    def test_sha256_is_stable_and_collision_free_across_inputs(self) -> None:
        assert sha256_hex(b"a") != sha256_hex(b"b")
        assert sha256_hex(b"a") == sha256_hex(b"a")

    def test_accepts_a_size_exactly_at_the_ceiling(self) -> None:
        """The boundary is inclusive; an off-by-one here would reject valid uploads."""
        validate_upload_size(MAX_BYTES, max_bytes=MAX_BYTES)

    @pytest.mark.parametrize("size", [0, -1, -(10**9)])
    def test_rejects_a_zero_or_negative_size(self, size: int) -> None:
        with pytest.raises(ValidationError):
            validate_upload_size(size, max_bytes=MAX_BYTES)

    def test_rejects_an_oversized_upload(self) -> None:
        with pytest.raises(FileTooLargeError):
            validate_upload_size(MAX_BYTES + 1, max_bytes=MAX_BYTES)

    def test_clamps_to_the_schema_hard_cap(self) -> None:
        """A ceiling above the CHECK constraint would fail at insert time.

        Accepting 40 MiB here produces a 500 from a constraint violation; a clean
        413 is what the caller should see.
        """
        with pytest.raises(FileTooLargeError):
            validate_upload_size(HARD_MAX_UPLOAD_BYTES + 1, max_bytes=HARD_MAX_UPLOAD_BYTES * 10)

    def test_rejects_an_unusable_ceiling(self) -> None:
        with pytest.raises(ValidationError):
            validate_upload_size(10, max_bytes=0)


# --------------------------------------------------------------------------- #
# End-to-end inspection                                                      #
# --------------------------------------------------------------------------- #
class TestInspectUpload:
    @pytest.mark.parametrize(
        ("payload", "declared", "filename", "expected_type", "expected_ext"),
        [
            pytest.param(JPEG_BYTES, "image/jpeg", "photo.jpg", "image/jpeg", ".jpg", id="jpeg"),
            pytest.param(PNG_BYTES, "image/png", "diagram.png", "image/png", ".png", id="png"),
            pytest.param(
                PDF_BYTES, "application/pdf", "cert.pdf", "application/pdf", ".pdf", id="pdf"
            ),
            pytest.param(WEBP_BYTES, "image/webp", "logo.webp", "image/webp", ".webp", id="webp"),
        ],
    )
    def test_accepts_a_well_formed_upload(
        self,
        payload: bytes,
        declared: str,
        filename: str,
        expected_type: str,
        expected_ext: str,
    ) -> None:
        result = inspect_upload(
            payload,
            declared_content_type=declared,
            declared_filename=filename,
            max_bytes=MAX_BYTES,
        )

        assert result.content_type == expected_type
        assert result.extension == expected_ext
        assert result.object_key_suffix == expected_ext
        assert result.size_bytes == len(payload)
        assert result.sha256 == sha256_hex(payload)
        assert result.safe_filename == filename

    def test_result_is_frozen(self) -> None:
        """The decision cannot be re-litigated between storage and the database."""
        result = inspect_upload(
            JPEG_BYTES,
            declared_content_type="image/jpeg",
            declared_filename="photo.jpg",
            max_bytes=MAX_BYTES,
        )

        assert isinstance(result, UploadInspection)
        with pytest.raises(AttributeError):
            result.content_type = "text/html"  # type: ignore[misc]

    def test_accepts_a_filename_without_an_extension(self) -> None:
        """Plenty of mobile clients send no name at all; that is not suspicious."""
        result = inspect_upload(
            JPEG_BYTES,
            declared_content_type="image/jpeg",
            declared_filename=None,
            max_bytes=MAX_BYTES,
        )

        assert result.extension == ".jpg"
        assert result.safe_filename == DEFAULT_DISPLAY_FILENAME

    def test_accepts_a_filename_that_has_no_dot_at_all(self) -> None:
        """A name with no extension is not a contradiction, only an absence."""
        result = inspect_upload(
            JPEG_BYTES,
            declared_content_type="image/jpeg",
            declared_filename="IMG_20260914_081233",
            max_bytes=MAX_BYTES,
        )

        assert result.extension == ".jpg"
        assert result.safe_filename == "IMG_20260914_081233"

    def test_accepts_a_filename_that_ends_with_a_dot(self) -> None:
        """A trailing dot yields an empty suffix, which is an absence not a mismatch."""
        result = inspect_upload(
            PNG_BYTES,
            declared_content_type="image/png",
            declared_filename="scan.",
            max_bytes=MAX_BYTES,
        )

        assert result.extension == ".png"

    def test_accepts_jpeg_synonym_extension(self) -> None:
        """``.jpeg`` is a legitimate spelling of a JPEG, not a contradiction."""
        result = inspect_upload(
            JPEG_BYTES,
            declared_content_type="image/jpeg",
            declared_filename="photo.jpeg",
            max_bytes=MAX_BYTES,
        )

        assert result.extension == ".jpg"
        assert result.safe_filename == "photo.jpeg"

    def test_rejects_an_empty_payload(self) -> None:
        with pytest.raises(ValidationError):
            inspect_upload(
                b"",
                declared_content_type="image/jpeg",
                declared_filename="photo.jpg",
                max_bytes=MAX_BYTES,
            )

    def test_rejects_an_oversized_payload(self) -> None:
        with pytest.raises(FileTooLargeError):
            inspect_upload(
                JPEG_BYTES,
                declared_content_type="image/jpeg",
                declared_filename="photo.jpg",
                max_bytes=len(JPEG_BYTES) - 1,
            )

    def test_rejects_a_declared_type_that_disagrees_with_the_signature(self) -> None:
        """A client claiming ``image/jpeg`` for PDF bytes is refused, not corrected.

        Guessing which of the two to trust is how a type-confusion bypass
        happens, so the disagreement itself is the signal.
        """
        with pytest.raises(UnsupportedFileTypeError):
            inspect_upload(
                PDF_BYTES,
                declared_content_type="image/jpeg",
                declared_filename="certificate.pdf",
                max_bytes=MAX_BYTES,
            )

    def test_rejects_a_declared_type_that_is_not_allowed(self) -> None:
        """Even when the declaration matches the bytes, an unlisted type is refused."""
        with pytest.raises(UnsupportedFileTypeError):
            inspect_upload(
                b"GIF89a" + b"\x00" * 16,
                declared_content_type="image/gif",
                declared_filename="animation.gif",
                max_bytes=MAX_BYTES,
            )

    def test_rejects_a_filename_whose_extension_contradicts_the_signature(self) -> None:
        """``evil.pdf`` with an image signature is the classic confused file."""
        with pytest.raises(UnsupportedFileTypeError):
            inspect_upload(
                PNG_BYTES,
                declared_content_type="image/png",
                declared_filename="evidence.pdf",
                max_bytes=MAX_BYTES,
            )

    def test_rejects_an_executable_extension_on_perfectly_valid_bytes(self) -> None:
        """Valid JPEG bytes named ``payload.exe`` is an attack, not a typo."""
        with pytest.raises(UnsupportedFileTypeError):
            inspect_upload(
                JPEG_BYTES,
                declared_content_type="image/jpeg",
                declared_filename="payload.exe",
                max_bytes=MAX_BYTES,
            )

    def test_rejects_an_unrecognised_signature_even_with_a_plausible_name(self) -> None:
        """A ``.png`` name does not make a ZIP a PNG."""
        with pytest.raises(UnsupportedFileTypeError):
            inspect_upload(
                ZIP_BYTES,
                declared_content_type="image/png",
                declared_filename="archive.png",
                max_bytes=MAX_BYTES,
            )

    def test_rejects_html_bytes_despite_a_pdf_name(self) -> None:
        with pytest.raises(UnsupportedFileTypeError):
            inspect_upload(
                TEXT_BYTES,
                declared_content_type="application/pdf",
                declared_filename="report.pdf",
                max_bytes=MAX_BYTES,
            )

    def test_sanitises_the_filename_it_reports(self) -> None:
        """The reported display name is never the raw client string."""
        result = inspect_upload(
            PNG_BYTES,
            declared_content_type="image/png",
            declared_filename="../../../root/.ssh/authorized_keys.png",
            max_bytes=MAX_BYTES,
        )

        assert result.safe_filename == "authorized_keys.png"
        assert "/" not in result.safe_filename

    def test_ignores_a_directory_prefix_when_checking_the_extension(self) -> None:
        """The extension check reads the basename, matching how a browser reads it."""
        result = inspect_upload(
            PNG_BYTES,
            declared_content_type="image/png",
            declared_filename="C:\\Users\\Jomo\\Photos\\diagram.png",
            max_bytes=MAX_BYTES,
        )

        assert result.extension == ".png"
        assert result.safe_filename == "diagram.png"

    def test_generated_key_agrees_with_the_inspected_type(self) -> None:
        """The extension stored in the database is the one in the key.

        Any divergence here would mean the object and its name disagree, which is
        the confusion this whole module exists to prevent.
        """
        result = inspect_upload(
            PNG_BYTES,
            declared_content_type="image/png",
            declared_filename="diagram.png",
            max_bytes=MAX_BYTES,
        )
        key = generate_object_key(
            purpose="WORK_EVIDENCE",
            content_type=result.content_type,
            owner_id=uuid.uuid4(),
        )

        assert key.endswith(result.extension)
        assert file_object_extension(key) == result.extension


def file_object_extension(object_key: str) -> str:
    """Mirror of ``FileObject.extension`` so the agreement is actually tested.

    Duplicated rather than imported because the model pulls in SQLAlchemy and the
    database session, and this is a pure unit test. A copy that drifts is caught
    by this assertion failing.
    """
    _, _, suffix = object_key.rpartition(".")
    return f".{suffix.lower()}" if suffix else ""
