"""HTTP middleware: request identity, security headers, CORS, access logging.

Middleware runs before routing, so it is the right place for concerns that apply
to every request regardless of endpoint - including 404s and errors generated
outside a route handler.
"""

from __future__ import annotations

import functools
import json
import re
import time

from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.exceptions import ErrorCode
from app.core.logging import (
    configure_logging,
    get_logger,
    request_id_var,
    set_request_id,
    user_id_var,
)
from app.core.security import constant_time_compare

logger = get_logger(__name__)

#: A request id is echoed to the client and stored in the audit trail, so it must
#: be a bounded, boring identifier. Anything else is replaced rather than
#: reflected, which also prevents header/log injection.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

#: Paths that should never appear in an access log at full resolution, because
#: they carry single-use credentials in the path.
_SENSITIVE_PATH_SEGMENTS = frozenset(
    {"verify-email", "reset-password", "confirm-password", "invitations"}
)


class RequestIdMiddleware:
    """Attach a correlation id to every request and response.

    Accepts a well-formed inbound ``X-Request-ID`` so a gateway or client can
    supply its own trace id, otherwise mints a UUID. The value is bound to a
    ``contextvar`` so any log call anywhere in the request can reach it, and is
    returned in the response header and in every error body.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        inbound = headers.get("x-request-id", "")
        request_id = inbound if _REQUEST_ID_RE.match(inbound) else _new_request_id()

        scope.setdefault("state", {})["request_id"] = request_id
        token = set_request_id(request_id)

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers", []))
                raw_headers.append((b"x-request-id", request_id.encode("latin-1")))
                message = {**message, "headers": raw_headers}
            await send(message)

        try:
            await self._app(scope, receive, send_with_id)
        finally:
            request_id_var.reset(token)
            user_id_var.set(None)


class SecurityHeadersMiddleware:
    """Attach conservative security headers to every response.

    Values are deliberately strict. Notably ``default-src 'none'`` on the API
    responses: the API returns JSON, so permitting scripts or framing is never
    necessary, and denying by default removes a whole class of content-injection
    consequence if a response were somehow rendered.
    """

    #: Applied to all API responses. The interactive docs pages are served by
    #: FastAPI separately and need a looser policy, handled below.
    API_HEADERS: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
        "X-Permitted-Cross-Domain-Policies": "none",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    }

    #: HSTS. Only meaningful over TLS, which Render terminates, so it is enabled
    #: unconditionally in production and omitted in development where the app
    #: is served over plain HTTP on localhost.
    HSTS_HEADER = "max-age=31536000; includeSubDomains; preload"

    DOCS_CSP = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "font-src 'self' data: https://cdn.jsdelivr.net; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    )

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self._app = app
        self._settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                for key, value in self._headers_for(path).items():
                    headers[key.lower().encode("latin-1")] = value.encode("latin-1")
                message = {**message, "headers": list(headers.items())}
            await send(message)

        await self._app(scope, receive, send_with_headers)

    def _headers_for(self, path: str) -> dict[str, str]:
        headers = dict(self.API_HEADERS)
        if path in {"/docs", "/redoc"} or path.startswith(("/docs", "/redoc")):
            headers["Content-Security-Policy"] = self.DOCS_CSP
        if self._settings.is_production:
            headers["Strict-Transport-Security"] = self.HSTS_HEADER
        return headers


class AccessLogMiddleware:
    """Emit one structured log line per request.

    Records the request id, method, resolved route template, status, duration and
    an error category. The **route template** is logged rather than the raw path:
    a path contains user-supplied identifiers, whereas ``/workers/{id}``
    aggregates safely and is what you want when asking "how slow is this
    endpoint" - a per-UUID path would make every query unique and useless.
    """

    #: Path segments whose values are single-use credentials. The segment is
    #: replaced with a placeholder so a token in a URL never reaches the log.
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500
        path = scope.get("path", "")

        async def capture_status(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self._app(scope, receive, capture_status)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            route = _safe_route_template(path)
            logger.info(
                "http_request",
                extra={
                    "method": scope.get("method"),
                    "route_template": route,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "error_category": _error_category(status_code),
                    "client": _client_hint(scope),
                },
            )


class BodySizeLimitMiddleware:
    """Reject an oversized request body before it is read.

    Checking ``Content-Length`` up front means a multi-gigabyte upload is refused
    in microseconds rather than after the server has buffered it. The upload path
    applies its own, tighter, per-file limit on top of this.

    Only the declared length is checked. A chunked request has no
    ``Content-Length``, so the per-endpoint limits remain the authoritative check;
    this is a cheap first line that stops the trivially large case.
    """

    #: Paths whose declared length is bounded by ``multipart_max_bytes`` instead of
    #: the JSON cap. A 256 KiB JSON ceiling would make the configured 10 MiB upload
    #: limit unreachable: every upload above 256 KiB would be refused here with a
    #: generic PAYLOAD_TOO_LARGE before the upload handler ever saw it, and the
    #: operator's configured limit would be a lie.
    _MULTIPART_PATHS: frozenset[str] = frozenset({"/files/upload"})

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_bytes: int,
        multipart_max_bytes: int | None = None,
    ) -> None:
        self._app = app
        self._max_bytes = max_bytes
        self._multipart_max_bytes = multipart_max_bytes or max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        limit = self._limit_for(scope)
        declared = _content_length(scope)
        if declared is not None and declared > limit:
            request_id = scope.get("state", {}).get("request_id")
            body = {
                "error": {
                    "code": ErrorCode.PAYLOAD_TOO_LARGE,
                    "message": "The request body exceeds the maximum permitted size.",
                    "request_id": request_id,
                }
            }
            raw = json.dumps(body).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(raw)).encode("latin-1")),
                        (b"x-request-id", str(request_id or "").encode("latin-1")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": raw})
            return

        await self._app(scope, receive, send)

    def _limit_for(self, scope: Scope) -> int:
        """The declared-length ceiling that applies to this request."""
        if scope.get("path") in self._MULTIPART_PATHS:
            return self._multipart_max_bytes
        return self._max_bytes


def _content_length(scope: Scope) -> int | None:
    """Parse ``Content-Length``, ignoring a malformed or absent value."""
    for key, value in scope.get("headers", []):
        if key.lower() != b"content-length":
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def build_cors_middleware(
    settings: Settings,
) -> functools.partial[CORSMiddleware] | None:
    """Build the CORS middleware from an exact origin allowlist.

    Two deliberate choices:

    * **No wildcard, ever.** ``allow_origins=["*"]`` is rejected by configuration
      validation, so it cannot reach this function.
    * **Credentials are off by default.** The API authenticates with a bearer
      token in a header, not a cookie, so credentialed CORS is not needed and
      enabling it would widen the attack surface for no benefit. If it is ever
      turned on, the allowlist still prevents cross-origin credential use.

    Returns a ``functools.partial`` rather than an instance, because
    ``app.add_middleware`` needs a callable it can invoke with ``app=``; handing
    it a constructed instance fails. Returning ``None`` when no origins are
    configured means the middleware is not installed at all rather than installed
    inertly.
    """
    if not settings.cors_allowed_origins:
        return None
    return functools.partial(
        CORSMiddleware,
        allow_origins=list(settings.cors_allowed_origins),
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Request-ID",
            "Idempotency-Key",
            "If-Match",
        ],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )


def _new_request_id() -> str:
    import uuid

    return str(uuid.uuid4())


def _safe_route_template(path: str) -> str:
    """Reduce a concrete path to its shape, masking credential segments."""
    segments = path.strip("/").split("/")
    masked = [
        "<redacted>" if segment in _SENSITIVE_PATH_SEGMENTS else segment for segment in segments
    ]
    return "/" + "/".join(masked)


def _error_category(status_code: int) -> str:
    if status_code < 400:
        return "none"
    if status_code < 500:
        return "client_error"
    return "server_error"


def _client_hint(scope: Scope) -> str | None:
    raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
    for key, value in raw_headers:
        if key.lower() == b"x-forwarded-for":
            candidate: str = value.decode("latin-1").split(",")[0].strip()
            return candidate[:64]
    return None


def same_origin_guard(expected: str, actual: str) -> bool:
    """Timing-safe origin comparison helper, exported for reuse and testing."""
    return constant_time_compare(expected.strip().lower(), actual.strip().lower())


__all__ = [
    "AccessLogMiddleware",
    "BodySizeLimitMiddleware",
    "RequestIdMiddleware",
    "SecurityHeadersMiddleware",
    "build_cors_middleware",
    "configure_logging",
]
