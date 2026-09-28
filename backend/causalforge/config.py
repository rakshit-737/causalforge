"""Application settings with safe local defaults.

Settings are intentionally explicit about lab mode and external network access. The default
configuration is local-only and uses SQLite so the health endpoint and contract tests work before
PostgreSQL is provisioned.
"""

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from causalforge import __version__

Environment = Literal["local", "test", "lab", "production"]


class Settings(BaseSettings):
    """Validated runtime configuration for the Phase 1 application shell."""

    model_config = SettingsConfigDict(
        env_prefix="CF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    app_name: str = "CausalForge"
    version: str = __version__
    environment: Environment = "local"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    database_url: str = Field(default="sqlite:///./causalforge.db", repr=False)
    database_echo: bool = False
    auto_create_schema: bool = False
    readiness_require_database: bool = True
    dependency_timeout_seconds: float = Field(default=2.0, ge=0.1, le=5.0)

    redis_url: str = Field(default="redis://127.0.0.1:6379/0", repr=False)
    readiness_require_redis: bool = False

    lab_only: bool = True
    external_network_enabled: bool = False

    @model_validator(mode="after")
    def validate_safety_defaults(self) -> "Settings":
        """Reject unsafe combinations before the application starts."""

        if self.environment == "production" and self.auto_create_schema:
            raise ValueError("auto_create_schema must be false in production")
        if self.environment == "production":
            raise ValueError("production mode is unsupported until authentication is implemented")
        if not self.lab_only or self.external_network_enabled:
            raise ValueError("lab_only must remain true and external network access disabled")
        if self.debug or self.database_echo:
            raise ValueError("debug traces and SQL echo are disabled to protect sensitive values")
        try:
            database = make_url(self.database_url)
            redis = urlsplit(self.redis_url)
            redis_port = redis.port
        except (ArgumentError, ValueError):
            raise ValueError("invalid dependency URL") from None
        if database.drivername not in {"sqlite", "postgresql+psycopg"}:
            raise ValueError("only SQLite and PostgreSQL with psycopg are supported")
        if database.query:
            raise ValueError("database URL query options are not supported in the local profile")
        if database.drivername == "sqlite":
            if database.host or database.username or database.password:
                raise ValueError("SQLite must use a local file or in-memory database")
        else:
            if database.host not in {"localhost", "127.0.0.1", "::1", "postgres"}:
                raise ValueError("database host must be loopback or the local postgres service")
            if self.auto_create_schema:
                raise ValueError("auto_create_schema is SQLite-only; use Alembic for PostgreSQL")
        if redis.scheme not in {"redis", "rediss"} or redis.query or redis.fragment:
            raise ValueError("Redis requires a redis/rediss URL without query options")
        if redis.hostname not in {"localhost", "127.0.0.1", "::1", "redis"}:
            raise ValueError("Redis host must be loopback or the local redis service")
        if redis_port is not None and not 1 <= redis_port <= 65535:
            raise ValueError("invalid Redis port")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide immutable settings object."""

    return Settings()


def redacted_url(url: str) -> str:
    """Return a log-safe URL without credentials or query values."""

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return "<invalid-url>"
    if parsed.scheme not in {"sqlite", "postgresql+psycopg", "redis", "rediss"}:
        return "<invalid-url>"
    if ":" in hostname:
        hostname = f"[{hostname}]"
    netloc = f"{hostname}{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
