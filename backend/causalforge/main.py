"""FastAPI application factory for the CausalForge control plane."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from causalforge.api.routes_events import router as events_router
from causalforge.api.routes_health import router as health_router
from causalforge.api.routes_incidents import router as incidents_router
from causalforge.config import Settings, get_settings
from causalforge.detection.sigma_engine import load_rules
from causalforge.observability.logging import configure_logging, get_logger
from causalforge.observability.middleware import RequestContextMiddleware
from causalforge.security.engine import DeterministicCaseEngine
from causalforge.storage.db import Database
from causalforge.storage.health import DatabaseProbe, ReadinessRegistry, RedisProbe, StaticProbe


def create_app(
    settings: Settings | None = None,
    case_engine: DeterministicCaseEngine | None = None,
) -> FastAPI:
    """Create an application with explicit settings and lifecycle-managed resources."""

    runtime_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(runtime_settings.log_level)
        logger = get_logger(__name__)
        database: Database = app.state.database
        if runtime_settings.auto_create_schema:
            database.create_schema()
        logger.info("causalforge_started environment=%s", runtime_settings.environment)
        try:
            yield
        finally:
            database.dispose()
            logger.info("causalforge_stopped")

    app = FastAPI(
        title=runtime_settings.app_name,
        version=runtime_settings.version,
        debug=runtime_settings.debug,
        lifespan=lifespan,
    )

    @app.exception_handler(RequestValidationError)
    async def safe_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Never echo unredacted request bodies from boundary validation errors."""

        del request, exc
        return JSONResponse(
            status_code=422,
            content={"code": "validation_error", "detail": "request validation failed"},
        )

    app.state.settings = runtime_settings
    rules_dir = Path(__file__).resolve().parents[2] / "rules" / "sigma"
    app.state.case_engine = case_engine or DeterministicCaseEngine(rules=load_rules(rules_dir))
    app.state.database = Database(
        runtime_settings.database_url,
        echo=runtime_settings.database_echo,
    )
    app.state.readiness = ReadinessRegistry(
        probes=(
            DatabaseProbe(
                app.state.database,
                required=runtime_settings.readiness_require_database,
                require_schema=not runtime_settings.auto_create_schema,
            ),
            RedisProbe(
                runtime_settings.redis_url,
                required=True,
                timeout_seconds=runtime_settings.dependency_timeout_seconds,
            )
            if runtime_settings.readiness_require_redis
            else StaticProbe(name="redis", detail="not_required_in_profile"),
        )
    )
    app.add_middleware(RequestContextMiddleware)
    app.include_router(health_router)
    app.include_router(events_router)
    app.include_router(incidents_router)
    return app


app = create_app()
