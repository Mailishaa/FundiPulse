"""Attach ``X-RateLimit-*`` to responses that were limited.

A limit whose headers appear only on the 429 leaves a client unable to pace itself
until it has already been refused. This reads the decision the route's dependency
stashed on ``request.state`` and copies its headers onto the response, on success
as well as on failure.

Deliberately separate from :class:`BodySizeLimitMiddleware` rather than folded into
it: a request may be rate-limited by identity and size-limited by framing, and
merging them would make one policy depend on the other's ordering.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

#: Headers copied from the decision onto the response.
RATE_LIMIT_HEADERS = (
    b"x-ratelimit-limit",
    b"x-ratelimit-remaining",
    b"x-ratelimit-reset",
    b"retry-after",
)


class RateLimitHeaderMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                decision = scope.get("state", {}).get("rate_limit_decision")
                if decision is not None:
                    self._merge(message, decision.standard_headers())
            await send(message)

        await self._app(scope, receive, send_wrapper)

    @staticmethod
    def _merge(message: MutableMapping[str, Any], headers: dict[str, str]) -> None:
        # `standard_headers()` returns canonical HTTP casing ("X-RateLimit-Limit")
        # while the tuple below is lowercase, so match case-insensitively. A silent
        # mismatch would drop every header on the success path while the 429 - which
        # sets them through the error handler - looked perfectly correct.
        lowered = {name.lower(): value for name, value in headers.items()}
        existing = list(message.get("headers", []))
        present = {bytes(key).lower() for key, _ in existing}

        for name in RATE_LIMIT_HEADERS:
            if name in present:
                # Never overwrite: a route that already set Retry-After (a 503,
                # say) keeps its value, which is more specific than ours.
                continue
            value = lowered.get(name.decode("latin-1"))
            if value is not None:
                existing.append((name, value.encode("latin-1")))

        message["headers"] = existing
