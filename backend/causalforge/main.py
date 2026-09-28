"""FastAPI application factory for the CausalForge control plane."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from causalforge.api.routes_health import router as health_router
from causalforge.config import Settings, get_settings
from causalforge.observability.logging import configure_logging, get_logger
from causalforge.observability.middleware import RequestContextMiddleware
from causalforge.storage.db import Database
from causalforge.storage.health import DatabaseProbe, ReadinessRegistry, RedisProbe, StaticProbe


def create_app(settings: Settings | None = None) -> FastAPI:
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
    app.state.settings = runtime_settings
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
    return app


app = create_app()
