"""FastAPI dependency accessors."""

from typing import cast

from fastapi import Request

from causalforge.config import Settings
from causalforge.security.engine import DeterministicCaseEngine
from causalforge.storage.db import Database
from causalforge.storage.health import ReadinessRegistry


def get_settings(request: Request) -> Settings:
    """Read immutable settings from application state."""

    return cast(Settings, request.app.state.settings)


def get_database(request: Request) -> Database:
    """Read the application-owned database boundary from application state."""

    return cast(Database, request.app.state.database)


def get_readiness(request: Request) -> ReadinessRegistry:
    """Read the dependency readiness registry from application state."""

    return cast(ReadinessRegistry, request.app.state.readiness)


def get_case_engine(request: Request) -> DeterministicCaseEngine:
    """Read the deterministic case engine from application state."""

    return cast(DeterministicCaseEngine, request.app.state.case_engine)
