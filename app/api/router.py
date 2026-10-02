"""Top-level API router.

One place where every domain router is mounted, so the version prefix is applied
exactly once and the endpoint inventory is reviewable at a glance.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import auth, catalogue, health, users, workers

#: Health probes are unversioned. A load balancer points at a fixed path, and
#: versioning it would mean an infrastructure change for every future API version.
health_router = APIRouter()
health_router.include_router(health.router)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.me_router)
api_router.include_router(users.admin_router)
api_router.include_router(workers.router)
api_router.include_router(catalogue.router)
api_router.include_router(catalogue.admin_router)

__all__ = ["api_router", "health_router"]
