"""Exception handlers: every failure becomes the same JSON envelope.

The contract, for every error the API returns:

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found.",
    "request_id": "0f1c...",
    "details": []
  }
}
```

Two properties this file is responsible for:

1. **No stack traces, ever, in production.** An unexpected exception is logged
   with its request id and replaced by a generic ``INTERNAL_ERROR``. The client
   gets the request id, which is enough for support to find the full detail in
   the logs, and not enough to learn anything about the server.
2. **Database errors are never echoed.** An ``IntegrityError`` becomes a
   ``409 CONFLICT`` or a ``500`` with a fixed message. A raw driver error can
   contain a fragment of the failing statement, which is a schema disclosure.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, cast

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from app.core.config import get_settings
from app.core.exceptions import (
    AppError,
    ErrorCode,
    InternalServerError,
    NotFoundError,
    RateLimitExceededError,
    ServiceUnavailableError,
    ValidationError,
)
from app.core.logging import get_logger, request_id_var

logger = get_logger(__name__)


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None) or request_id_var.get()


def _error_response(
    request: Request,
    *,
    code: str,
    message: str,
    status_code: int,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build the standard error response."""
    body: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "request_id": _request_id(request),
        }
    }
    if details:
        body["error"]["details"] = details
    response_headers = dict(headers or {})
    response_headers.setdefault("X-Request-ID", _request_id(request) or "")
    return JSONResponse(
        status_code=status_code,
        content=jsonable_encoder(body),
        headers=response_headers,
    )


# --------------------------------------------------------------------------- #
# Handlers                                                                   #
# --------------------------------------------------------------------------- #
async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Render an intentional :class:`AppError`."""
    details = [detail.as_dict() for detail in exc.details]
    if exc.status_code >= 500:
        logger.error(
            exc.code,
            extra={"error_category": "application_error", "path": request.url.path},
        )
    return _error_response(
        request,
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        details=details,
        headers=exc.headers,
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Render FastAPI request validation as ``VALIDATION_FAILED``.

    Field-level messages are passed through because they describe the client's own
    input and are the single most useful thing a mobile form can show a user.
    """
    details = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", []) if part != "body")
        details.append(
            {
                "field": location or None,
                "message": error.get("msg", "Invalid value."),
                "code": error.get("type"),
            }
        )
    return _error_response(
        request,
        code=ErrorCode.VALIDATION_FAILED,
        message=ValidationError.public_message,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        details=details,
    )


async def pydantic_validation_handler(
    request: Request,
    exc: PydanticValidationError,  # noqa: ARG001 - signature fixed by Starlette's handler protocol
) -> JSONResponse:  # pragma: no cover - FastAPI normally wraps these
    return _error_response(
        request,
        code=ErrorCode.VALIDATION_FAILED,
        message=ValidationError.public_message,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )


async def integrity_error_handler(request: Request, exc: IntegrityError) -> JSONResponse:
    """Translate a constraint violation into a conflict.

    The driver message is logged server-side and **never returned**. It can
    contain column names, values and fragments of the failing statement, which is
    a schema disclosure and, where the value came from user input, a reflection
    attack surface.
    """
    logger.warning(
        "Database constraint violation",
        extra={
            "error_category": "integrity_error",
            "path": request.url.path,
            "constraint": _constraint_name(exc),
        },
    )
    return _error_response(
        request,
        code=ErrorCode.CONFLICT,
        message="The request conflicts with the current state of the data.",
        status_code=status.HTTP_409_CONFLICT,
    )


async def operational_error_handler(
    request: Request,
    exc: OperationalError,  # noqa: ARG001 - signature fixed by Starlette
) -> JSONResponse:
    """A database connectivity failure is a 503, not a 500.

    Distinguishing them lets a client retry safely: a 503 is transient, a 500 is
    not. The underlying error (hostnames, credentials) stays in the logs.
    """
    logger.error(
        "Database unavailable",
        extra={"error_category": "database_unavailable", "path": request.url.path},
    )
    return _error_response(
        request,
        code=ErrorCode.SERVICE_UNAVAILABLE,
        message=ServiceUnavailableError.public_message,
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        headers={"Retry-After": "5"},
    )


async def dbapi_error_handler(
    request: Request,
    exc: DBAPIError,  # noqa: ARG001 - signature fixed by Starlette's protocol
) -> JSONResponse:
    logger.error(
        "Database error",
        extra={"error_category": "database_error", "path": request.url.path},
    )
    return _error_response(
        request,
        code=ErrorCode.INTERNAL_ERROR,
        message=InternalServerError.public_message,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Normalise Starlette's ``HTTPException`` into the standard envelope.

    Without this, a 404 from the router or a 405 from routing would return a
    different body shape from every deliberate error, and a client would need two
    parsers.
    """
    if not isinstance(exc, StarletteHTTPException):
        return await unhandled_exception_handler(request, exc)

    code_by_status = {
        status.HTTP_404_NOT_FOUND: ErrorCode.ROUTE_NOT_FOUND,
        status.HTTP_405_METHOD_NOT_ALLOWED: ErrorCode.METHOD_NOT_ALLOWED,
        status.HTTP_401_UNAUTHORIZED: ErrorCode.AUTHENTICATION_REQUIRED,
        status.HTTP_403_FORBIDDEN: ErrorCode.FORBIDDEN,
        status.HTTP_429_TOO_MANY_REQUESTS: ErrorCode.RATE_LIMITED,
    }
    code = code_by_status.get(exc.status_code, ErrorCode.BAD_REQUEST)
    message = exc.detail if isinstance(exc.detail, str) else "The request could not be processed."

    headers = dict(getattr(exc, "headers", None) or {})
    if exc.status_code == status.HTTP_404_NOT_FOUND:
        message = NotFoundError.public_message

    return _error_response(
        request,
        code=code,
        message=message,
        status_code=exc.status_code,
        headers=headers,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last resort: log everything, return nothing useful.

    In development the traceback is included, because a developer needs it and
    the audience is a developer. In production it is not, because ``debug``
    cannot be relied on and the response would otherwise leak the stack.
    """
    # Read the settings bound to *this* application instance, not the process-wide
    # singleton. `create_app(settings)` is what makes an isolated app (tests, a
    # second instance) behave according to its own configuration; consulting
    # `get_settings()` here would ignore that and could expose a traceback on an
    # app that was deliberately built for production.
    settings = getattr(request.app.state, "settings", None) or get_settings()
    logger.error(
        "Unhandled exception",
        extra={
            "error_category": "unhandled",
            "path": request.url.path,
            "method": request.method,
            "exception_type": type(exc).__name__,
        },
        exc_info=exc,
    )

    details: list[dict[str, Any]] = []
    if settings.is_production:
        message = InternalServerError.public_message
    else:
        message = f"{type(exc).__name__}: {exc}"
        details.append(
            {
                "field": "debug",
                "message": "A traceback is included because the app is not in production.",
            }
        )

    return _error_response(
        request,
        code=ErrorCode.INTERNAL_ERROR,
        message=message,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        details=details,
    )


def _constraint_name(exc: IntegrityError) -> str | None:
    """Extract the violated constraint name for the log, if available.

    ``exc.orig`` carries the PostgreSQL ``Diag`` object, which gives
    ``constraint_name`` without parsing the message text.
    """
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    return getattr(diag, "constraint_name", None)


#: Starlette's ``add_exception_handler`` stub types the callback as accepting any
#: ``Exception``. Our handlers are narrower - ``IntegrityError``, ``AppError`` and
#: so on - which is correct at runtime, because Starlette dispatches on the exact
#: raised type. The stub cannot express that, so the cast happens once here
#: instead of an ignore on every registration.
_ExceptionHandler = Callable[[Request, Exception], Awaitable[Response]]


def _register(app: FastAPI, exception_type: type[Exception], handler: object) -> None:
    """Register one handler, hiding only the stub's overly-narrow signature."""
    app.add_exception_handler(exception_type, cast(_ExceptionHandler, handler))


def register_exception_handlers(app: FastAPI) -> None:
    """Attach every handler to the application.

    Order matters only in that Starlette resolves the most specific registered
    handler first; these are distinct exception types, so there is no shadowing.
    """
    _register(app, AppError, app_error_handler)
    _register(app, RequestValidationError, validation_error_handler)
    _register(app, PydanticValidationError, pydantic_validation_handler)
    _register(app, IntegrityError, integrity_error_handler)
    _register(app, OperationalError, operational_error_handler)
    _register(app, DBAPIError, dbapi_error_handler)
    _register(app, RateLimitExceededError, app_error_handler)
    # Router-level 404/405 are raised by Starlette rather than by a route, so they
    # need an explicit handler or they would return FastAPI's `{"detail": ...}`
    # shape and every client would need a second error parser.
    _register(app, StarletteHTTPException, http_exception_handler)
    _register(app, Exception, unhandled_exception_handler)
