"""Top-level API router.

One place where every domain router is mounted, so the version prefix is applied
exactly once and the endpoint inventory is reviewable at a glance.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import auth, health, users

#: Health probes are **unversioned**.
#
#: A load balancer or orchestrator points at a fixed path. Versioning the health
#: endpoint means an infrastructure config change is required for every future API
#: version, and an orchestrator that cannot reach the health check restarts a
#: healthy service. The endpoint therefore has a deliberately boring, stable URL.
health_router = APIRouter()
health_router.include_router(health.router)

#: Everything else lives under the versioned prefix.
api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.me_router)
api_router.include_router(users.admin_router)

__all__ = ["api_router", "health_router"]
