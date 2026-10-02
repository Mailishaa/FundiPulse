"""Structured logging and the per-request correlation context.

Logging here is deliberately built on the standard library rather than a
third-party framework. The requirement is small - emit JSON with a fixed field
vocabulary - and every additional dependency is supply-chain surface on a service
that handles credentials.

Design:

* **JSON to stdout in production** so Render's log collector can ingest it;
  human-readable locally.
* **A ``contextvar`` carries the request id** so any log call anywhere in a
  request can reach it without the value being threaded through every function
  signature. Worker threads see no context, and the formatter tolerates that.
* **An explicit redaction layer.** Secrets are dropped by *key name*, before
  formatting, not by hoping the call site remembered.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from datetime import UTC, datetime
import json
import logging
import sys
from typing import Any, Final
import uuid

from app.core.config import Settings, get_settings

#: Holds the current request id, or ``None`` outside a request.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)

#: Log record attributes that come from the logging framework itself.
_RESERVED_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

#: Keys whose values must never reach a log sink. Matched case-insensitively as
#: a substring, so ``access_token``, ``newPassword`` and ``X-Access-Token`` are
#: all caught.
SENSITIVE_KEY_SUBSTRINGS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "auth_header",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "session_id",
    "sessionid",
    "refresh",
    "cookie",
    "set-cookie",
    "signed_url",
    "otp",
    "signature",
)

REDACTED = "[REDACTED]"


#: Separators that appear interchangeably in header and field names. Normalising
#: them before matching is what stops ``Api-Key`` or ``api.key`` from sailing past
#: a check that catches ``api_key``.
_SEPARATOR_TRANSLATION = str.maketrans({"-": "_", ".": "_", " ": "_"})


def normalise_key(key: str) -> str:
    """Lower-case and unify separators so matching is separator-agnostic."""
    return key.lower().translate(_SEPARATOR_TRANSLATION)


def is_sensitive_key(key: str) -> bool:
    """Whether a field name looks like it carries a secret."""
    normalised = normalise_key(key)
    return any(marker in normalised for marker in SENSITIVE_KEY_SUBSTRINGS)


def redact(value: Any) -> Any:
    """Recursively drop sensitive fields from a structure.

    Applied to the ``extra`` payload before serialisation, so a caller that
    logs ``extra={"refresh_token": token}`` gets ``[REDACTED]`` rather than a
    credential in a log aggregator with weaker access control than the database.
    """
    if isinstance(value, dict):
        return {
            key: (REDACTED if is_sensitive_key(str(key)) else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(item) for item in value]
    return value


class RequestContextFilter(logging.Filter):
    """Inject the request id and user id into every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id_var.get()
        if not hasattr(record, "user_id"):
            record.user_id = user_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    """Serialise a record as one JSON object per line."""

    def __init__(self, service_name: str) -> None:
        super().__init__()
        self._service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "service": self._service_name,
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
            "request_id": getattr(record, "request_id", None),
            "user_id": getattr(record, "user_id", None),
        }

        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_KEYS or key in payload:
                continue
            if key.startswith("_"):
                continue
            # Check the KEY before the value: `extra={"refresh_token": x}` is the
            # exact case that must not reach a log aggregator, and redacting the
            # value alone would leave the string intact.
            if is_sensitive_key(key):
                payload[key] = REDACTED
                continue
            payload[key] = redact(value)

        if record.exc_info:
            # The exception type and location are logged; the message of a
            # driver error can contain a fragment of a query, so it is redacted
            # by key name only where a specific field is passed. Stack traces in
            # logs are for operators, not clients.
            exc_type, exc_value, _ = record.exc_info
            payload["error_type"] = getattr(exc_type, "__name__", str(exc_type))
            payload["error"] = str(exc_value)

        return json.dumps(payload, default=str, separators=(",", ":"))


class HumanFormatter(logging.Formatter):
    """Readable single-line output for local development."""

    def format(self, record: logging.LogRecord) -> str:
        request_id = getattr(record, "request_id", None)
        prefix = f"[{request_id[:8]}] " if request_id else ""
        extras = {
            key: redact(value)
            for key, value in record.__dict__.items()
            if key not in _RESERVED_RECORD_KEYS
            and not key.startswith("_")
            and key not in {"request_id", "user_id", "event"}
        }
        suffix = f" {json.dumps(extras, default=str)}" if extras else ""
        base = f"{record.levelname:<7} {prefix}{record.getMessage()}{suffix}"
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


def configure_logging(settings: Settings | None = None) -> None:
    """Install the root handler. Idempotent, so tests may call it repeatedly."""
    settings = settings or get_settings()
    level = getattr(logging, settings.log_level, logging.INFO)

    handler = logging.StreamHandler(stream=sys.stdout)
    if settings.log_json:
        handler.setFormatter(JsonFormatter(service_name=settings.app_slug))
    else:
        handler.setFormatter(HumanFormatter())
    handler.addFilter(RequestContextFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn installs its own colourised handlers which bypass ours. Route its
    # logs through the root handler instead so access logs are also structured.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = True
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    # SQLAlchemy logs statements at INFO with echo, and at DEBUG otherwise.
    # Query text can contain values, so it stays off regardless.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.LoggerAdapter[logging.Logger]:
    """Return a logger adapter that stamps an ``event`` name on every record.

    Naming the event explicitly is what makes logs queryable: ``event ==
    "LOGIN_FAILURE"`` is an indexable predicate, whereas a free-text message is
    not.
    """

    class _Adapter(logging.LoggerAdapter[logging.Logger]):
        def process(self, msg: Any, kwargs: Any) -> tuple[Any, dict[str, Any]]:
            extra = dict(kwargs.get("extra") or {})
            extra.setdefault("event", msg if isinstance(msg, str) else str(msg))
            kwargs["extra"] = extra
            return msg, kwargs

    return _Adapter(logging.getLogger(name), {})


def set_request_id(value: str | None) -> Token[str | None]:
    """Bind a request id for the current context."""
    return request_id_var.set(value)


def new_request_id() -> str:
    return str(uuid.uuid4())


__all__ = [
    "REDACTED",
    "HumanFormatter",
    "JsonFormatter",
    "RequestContextFilter",
    "configure_logging",
    "get_logger",
    "is_sensitive_key",
    "new_request_id",
    "redact",
    "request_id_var",
    "set_request_id",
    "user_id_var",
]
