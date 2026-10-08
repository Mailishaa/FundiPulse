"""ASGI application factory.

The factory pattern is used rather than a module-level ``app`` for one concrete
reason: tests need several isolated application instances with different settings
and no shared middleware or router state. A module-level singleton would leak
configuration between test cases.

``app.main:app`` - the attribute the container runs - is created at import time
from environment configuration, so a misconfigured deployment fails on start-up
rather than on the first request.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.errors import register_exception_handlers
from app.api.middleware import (
    AccessLogMiddleware,
    BodySizeLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
    build_cors_middleware,
)
from app.api.rate_limit_middleware import RateLimitHeaderMiddleware
from app.api.router import api_router, health_router
from app.core.config import Settings, get_settings
from app.core.constants import API_DESCRIPTION, APP_NAME, APP_VERSION
from app.core.logging import configure_logging, get_logger
from app.db.session import reset_engine

logger = get_logger(__name__)

#: JSON body ceiling. Uploads have their own, tighter, per-file limit enforced in
#: the upload route, so this is a backstop for everything else.
MAX_JSON_BODY_BYTES = 256 * 1024

#: Headroom for multipart framing (boundaries, part headers, the trailing
#: delimiter). Without it a file of exactly `max_upload_size_bytes` would be
#: rejected because the envelope pushes the request over the ceiling.
MULTIPART_OVERHEAD_BYTES = 64 * 1024

DESCRIPTION = (
    API_DESCRIPTION
    + """

---

## Conventions

* **Base URL** - endpoints are unprefixed resource paths, e.g. `/auth/login`.
* **Authentication** - `Authorization: Bearer <access token>`. Access tokens are
  short-lived; refresh tokens are rotating and revocable.
* **Pagination** - every collection endpoint takes `?page=` and `?page_size=`
  (`page_size` is capped) and returns `meta.pagination`.
* **Errors** - always `{"error": {"code", "message", "request_id", "details"}}`.
  Codes are stable identifiers; branch on them rather than on `message`.
* **Concurrency** - the API is authoritative for authentication, authorisation,
  ownership, visibility, verification, job status and application state. Client
  controls are presentation, never enforcement.
* **Verification** - a recorded third-party attestation about a specific claim.
  It is **not** a background check, **not** a professional certification, and
  **not** a guarantee of competence or legitimacy.
"""
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start-up and shut-down.

    Runs before the first request is served. Configuration validation has already
    happened by the time this runs, because ``Settings`` is constructed first - so
    an unsafe production configuration prevents the port from ever opening.
    """
    settings: Settings = app.state.settings
    logger.info(
        "Application starting",
        extra={
            "app_version": APP_VERSION,
            "environment": settings.app_env,
            "docs_enabled": settings.enable_docs,
            "storage_backend": settings.storage_backend,
            "rate_limit_backend": settings.rate_limit_backend,
            "smtp_host": settings.email_smtp_host,
            "smtp_host_length": len(settings.email_smtp_host),
            "smtp_configured": settings.smtp_configured,
            "smtp_username_set": bool(settings.email_smtp_username),
            "smtp_from": settings.email_smtp_from,
        },
    )
    try:
        yield
    finally:
        logger.info("Application shutting down")
        # Dispose pooled connections explicitly rather than leaving them to the
        # garbage collector, so shutdown is prompt and does not leak sockets.
        reset_engine()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and configure an application instance."""
    resolved = settings or get_settings()
    configure_logging(resolved)

    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if resolved.enable_docs else None,
        redoc_url="/redoc" if resolved.enable_docs else None,
        openapi_url="/openapi.json",
        # The interactive UIs embed a CDN-hosted bundle. TrustedHostMiddleware and
        # the CSP set in SecurityHeadersMiddleware keep that from becoming an
        # XSS vector via a modified bundle; see docs/security.md.
        contact={"name": "FundiPulse Engineering"},
        license_info={"name": "Proprietary"},
        swagger_ui_parameters={"persistAuthorization": False},
    )
    app.state.settings = resolved

    # Middleware order matters. Starlette applies these outermost-first, so:
    #   request id  -> outermost, so even an error in another layer is traceable
    #   security headers
    #   CORS         -> before routes, so a preflight is answered
    #   body size    -> before the route reads the body
    #   access log   -> innermost, so it measures the route, not the wrapper
    app.add_middleware(AccessLogMiddleware)
    # The upload route carries a file, so it is bounded by the configured upload
    # limit plus multipart framing overhead rather than the JSON cap. Without this
    # a 10 MiB `max_upload_size_bytes` would be unreachable: anything over 256 KiB
    # would be refused here, before the upload handler ever ran.
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=MAX_JSON_BODY_BYTES,
        multipart_max_bytes=resolved.max_upload_size_bytes + MULTIPART_OVERHEAD_BYTES,
    )
    cors = build_cors_middleware(resolved)
    if cors is not None:
        app.add_middleware(cors)
    app.add_middleware(SecurityHeadersMiddleware, settings=resolved)
    app.add_middleware(RateLimitHeaderMiddleware)
    app.add_middleware(RequestIdMiddleware)

    register_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(api_router, prefix=resolved.api_v1_prefix)

    if resolved.enable_docs:
        _install_docs_routes(app)
    else:
        _install_docs_blocked(app)

    return app


def _install_docs_routes(app: FastAPI) -> None:
    """Serve Swagger/ReDoc with a locked-down CSP.

    FastAPI's default Swagger page loads its bundle from a CDN and uses inline
    styles, which the strict API CSP would block. The docs pages therefore get a
    deliberately narrower policy: no framing, no plugins, scripts restricted to
    self plus that one CDN.
    """
    from starlette.requests import Request

    @app.get("/docs", include_in_schema=False)
    async def custom_swagger(request: Request) -> HTMLResponse:  # pragma: no cover - UI
        return get_swagger_ui_html(
            openapi_url=str(request.app.openapi_url),
            title=f"{request.app.title} - API reference",
            swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
            swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
            swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        )

    @app.get("/redoc", include_in_schema=False)
    async def custom_redoc(request: Request) -> HTMLResponse:  # pragma: no cover - UI
        return get_redoc_html(
            openapi_url=str(request.app.openapi_url),
            title=f"{request.app.title} - API reference",
            redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js",
            redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        )


def _install_docs_blocked(app: FastAPI) -> None:
    """Make disabled documentation a clear 404 rather than a bare route miss."""

    @app.get("/docs", include_in_schema=False)
    async def docs_disabled() -> JSONResponse:  # pragma: no cover - trivial
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "ROUTE_NOT_FOUND",
                    "message": (
                        "Interactive documentation is disabled. The OpenAPI "
                        "schema remains available at /openapi.json."
                    ),
                    "request_id": None,
                }
            },
        )

    @app.get("/redoc", include_in_schema=False)
    async def redoc_disabled() -> JSONResponse:  # pragma: no cover - trivial
        return JSONResponse(status_code=404, content={"detail": "Not Found"})


#: The instance uvicorn loads: ``uvicorn app.main:app``.
#: Constructed at import time, so an invalid configuration raises here - during
#: container start-up - rather than on the first request.
app = create_app()
