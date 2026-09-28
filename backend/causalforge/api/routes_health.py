"""Liveness and readiness endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette import status

from causalforge import __version__
from causalforge.api.deps import get_readiness, get_settings
from causalforge.config import Settings
from causalforge.storage.health import ReadinessRegistry, ReadinessReport

router = APIRouter(prefix="/health", tags=["health"])


class LivenessResponse(BaseModel):
    """Response proving the process can serve requests."""

    model_config = ConfigDict(frozen=True)

    status: str
    service: str
    version: str
    environment: str


@router.get("/live", response_model=LivenessResponse)
def live(settings: Annotated[Settings, Depends(get_settings)]) -> LivenessResponse:
    """Return process liveness without checking external dependencies."""

    return LivenessResponse(
        status="ok",
        service=settings.app_name,
        version=settings.version or __version__,
        environment=settings.environment,
    )


@router.get("/ready", response_model=ReadinessReport)
def ready(
    readiness: Annotated[ReadinessRegistry, Depends(get_readiness)],
) -> ReadinessReport | JSONResponse:
    """Return 503 when a required dependency is unavailable."""

    report = readiness.evaluate()
    if report.status != "ready":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=report.model_dump(mode="json"),
        )
    return report
