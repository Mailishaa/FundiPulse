"""Health and readiness probes.

Three endpoints with three different purposes. Confusing them causes real outage
behaviour, so they are kept separate and deliberately terse.

| Endpoint | Meaning | Used by |
| --- | --- | --- |
| ``/health/live`` | The process is running and can serve traffic | Container orchestrator |
| ``/health/ready`` | Dependencies are reachable; send this traffic | Load balancer, Render |
| ``/health`` | Combined status for humans and dashboards | Monitoring |

**Liveness must not touch the database.** If it did, a database blip would
restart every healthy worker, turning a recoverable dependency failure into a
full outage.

**No diagnostic detail leaks.** No connection strings, hostnames, exception text
or query strings. These endpoints are reachable by anyone who can reach the
service, so a pool statistic or a version banner would be free reconnaissance.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Response, status
from pydantic import Field

from app.core.config import get_settings
from app.core.constants import APP_VERSION
from app.core.logging import get_logger
from app.db.session import check_database_connectivity, get_engine
from app.schemas.common import ApiModel, HealthStatus, Meta, ResponseEnvelope

router = APIRouter(tags=["Health"])
logger = get_logger(__name__)


class HealthResponse(ApiModel):
    """Health payload. Identical shape for all three probes."""

    status: str = Field(description="ok | degraded | down")
    version: str
    environment: str
    checks: dict[str, HealthStatus] = Field(
        default_factory=dict,
        description="Per-dependency results. Empty when nothing was probed.",
    )


@router.get(
    "/health",
    response_model=ResponseEnvelope[HealthResponse],
    summary="Aggregate service health",
    description=(
        "Reports liveness and dependency status together, for dashboards and "
        "human checks. Use `/health/live` and `/health/ready` for automation."
    ),
    responses={200: {"description": "Service is healthy."}},
    tags=["Health"],
)
def health(response: Response) -> ResponseEnvelope[HealthResponse]:
    database_started = time.perf_counter()
    database_ok = check_database_connectivity()
    database_latency = round((time.perf_counter() - database_started) * 1000, 2)

    if not database_ok:
        # 503 so an external monitor can alert on the status code alone. The
        # endpoint still answers with a body: a probe that 500s tells you less.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ResponseEnvelope(
        data=HealthResponse(
            status="ok" if database_ok else "degraded",
            version=APP_VERSION,
            environment=get_settings().app_env,
            checks={
                "database": HealthStatus(
                    status="ok" if database_ok else "down",
                    latency_ms=database_latency,
                )
            },
        ),
        meta=Meta(),
    )


@router.get(
    "/health/live",
    response_model=ResponseEnvelope[HealthResponse],
    summary="Liveness probe",
    description=(
        "Returns `200` whenever the process is running.\n\n"
        "**Deliberately does not check the database.** A liveness probe that fails "
        "on a dependency outage causes the orchestrator to restart every healthy "
        "instance, escalating a recoverable database problem into a total outage."
    ),
    responses={200: {"description": "The process is alive."}},
)
def liveness() -> ResponseEnvelope[HealthResponse]:
    return ResponseEnvelope(
        data=HealthResponse(
            status="ok",
            version=APP_VERSION,
            environment=get_settings().app_env,
            checks={},
        ),
        meta=Meta(),
    )


@router.get(
    "/health/ready",
    response_model=ResponseEnvelope[HealthResponse],
    summary="Readiness probe",
    description=(
        "Verifies database connectivity and returns `503` when the database is "
        "unreachable, so the load balancer stops sending traffic here.\n\n"
        "The payload discloses only a status and a latency figure."
    ),
    responses={
        200: {"description": "Ready to serve traffic."},
        503: {"description": "A dependency is unavailable."},
    },
)
def readiness(response: Response) -> ResponseEnvelope[HealthResponse]:
    started = time.perf_counter()
    database_ok = check_database_connectivity()
    latency = round((time.perf_counter() - started) * 1000, 2)

    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning("Readiness probe failed", extra={"error_category": "dependency_down"})

    return ResponseEnvelope(
        data=HealthResponse(
            status="ok" if database_ok else "down",
            version=APP_VERSION,
            environment=get_settings().app_env,
            checks={
                "database": HealthStatus(status="ok" if database_ok else "down", latency_ms=latency)
            },
        ),
        meta=Meta(),
    )


def get_database_pool_status() -> dict[str, Any]:
    """Pool statistics for operational diagnostics.

    Not exposed on a public endpoint: it reveals sizing and saturation, which is
    useful reconnaissance. Consumed by an operator script or a future internal
    metrics route.
    """
    from sqlalchemy.pool import QueuePool

    pool = get_engine().pool
    if not isinstance(pool, QueuePool):
        return {"pool_type": type(pool).__name__}
    return {
        "pool_type": "QueuePool",
        "size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
    }
