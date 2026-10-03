"""Top-level API router.

One place where every domain router is mounted, so the endpoint inventory is
reviewable at a glance. Paths are unprefixed resource paths; ``main.py`` applies
the (empty by default) mount prefix exactly once.

Mount order follows the product, not the alphabet: authentication, then the Work
Passport and everything hanging off it, then the employer side, then trust and
moderation, then the shared surfaces. A reader scanning this file should see the
shape of the product.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    applications,
    auth,
    catalogue,
    contact,
    credentials,
    discovery,
    files,
    health,
    jobs,
    notifications,
    organizations,
    references,
    reports,
    users,
    verifications,
    workers,
)

#: Health probes are unprefixed. A load balancer points at a fixed path, and
#: versioning it would mean an infrastructure change for every future API version.
health_router = APIRouter()
health_router.include_router(health.router)

api_router = APIRouter()

# Authentication and accounts.
api_router.include_router(auth.router)
api_router.include_router(users.me_router)
api_router.include_router(users.admin_router)

# The Work Passport and everything hanging off it.
api_router.include_router(workers.router)
api_router.include_router(discovery.router)
api_router.include_router(references.router)
api_router.include_router(credentials.router)

# Employer side.
api_router.include_router(organizations.router)
api_router.include_router(organizations.admin_router)
api_router.include_router(jobs.router)
api_router.include_router(applications.router)

# Trust and moderation.
api_router.include_router(verifications.router)
api_router.include_router(reports.router)
api_router.include_router(reports.admin_router)
api_router.include_router(files.router)
api_router.include_router(contact.router)

# Shared surfaces.
api_router.include_router(catalogue.router)
api_router.include_router(catalogue.admin_router)
api_router.include_router(notifications.router)

__all__ = ["api_router", "health_router"]
