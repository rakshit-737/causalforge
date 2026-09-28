"""Dependency readiness checks with safe, structured results."""

from dataclasses import dataclass
from time import monotonic
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

CheckStatus = Literal["ok", "error", "skipped"]
OverallReadinessStatus = Literal["ready", "not_ready"]


class ReadinessCheck(BaseModel):
    """Public, secret-free dependency check result."""

    model_config = ConfigDict(frozen=True)

    name: str
    status: CheckStatus
    required: bool
    detail: str
    latency_ms: float


class ReadinessReport(BaseModel):
    """Aggregate readiness result returned by the health API."""

    model_config = ConfigDict(frozen=True)

    status: OverallReadinessStatus
    checks: tuple[ReadinessCheck, ...]


class Probe(Protocol):
    """Minimal interface for a dependency health probe."""

    @property
    def name(self) -> str:
        """Stable dependency name."""

    @property
    def required(self) -> bool:
        """Whether a failed probe makes the application unready."""

    @property
    def enabled(self) -> bool:
        """Whether this dependency is configured for the current profile."""

    def check(self) -> None:
        """Raise if the dependency is unavailable."""


class Checkable(Protocol):
    """Minimal database-like interface required by ``DatabaseProbe``."""

    def check(self, *, require_schema: bool = False) -> None:
        """Run a connectivity and optional schema check."""


@dataclass(frozen=True)
class StaticProbe:
    """Represent an optional dependency that is intentionally disabled."""

    name: str
    required: bool = False
    detail: str = "disabled"
    enabled: bool = False

    def check(self) -> None:
        return None


class DatabaseProbe:
    """Adapt the database connectivity check to the generic probe interface."""

    name = "database"

    def __init__(self, database: "Checkable", *, required: bool, require_schema: bool) -> None:
        self.database = database
        self.required = required
        self.require_schema = require_schema
        self.enabled = True

    def check(self) -> None:
        self.database.check(require_schema=self.require_schema)


class RedisProbe:
    """Check Redis only when the configuration explicitly requires it."""

    name = "redis"
    enabled = True

    def __init__(self, url: str, *, required: bool, timeout_seconds: float) -> None:
        self.url = url
        self.required = required
        self.timeout_seconds = timeout_seconds

    def check(self) -> None:
        from redis import Redis

        client = Redis.from_url(
            self.url,
            socket_connect_timeout=self.timeout_seconds,
            socket_timeout=self.timeout_seconds,
            health_check_interval=30,
        )
        try:
            if not client.ping():
                raise RuntimeError("Redis ping failed")
        finally:
            client.close()


class ReadinessRegistry:
    """Evaluate all registered dependencies without leaking connection details."""

    def __init__(self, probes: tuple[Probe, ...]) -> None:
        self.probes = probes

    def evaluate(self) -> ReadinessReport:
        checks: list[ReadinessCheck] = []
        for probe in self.probes:
            if not probe.enabled:
                checks.append(
                    ReadinessCheck(
                        name=probe.name,
                        status="skipped",
                        required=probe.required,
                        detail=getattr(probe, "detail", "disabled"),
                        latency_ms=0.0,
                    )
                )
                continue
            started = monotonic()
            try:
                probe.check()
            except Exception as exc:  # noqa: BLE001 - health must convert driver errors safely
                checks.append(
                    ReadinessCheck(
                        name=probe.name,
                        status="error",
                        required=probe.required,
                        detail=type(exc).__name__,
                        latency_ms=round((monotonic() - started) * 1000, 2),
                    )
                )
            else:
                detail = getattr(probe, "detail", "ok")
                checks.append(
                    ReadinessCheck(
                        name=probe.name,
                        status="ok",
                        required=probe.required,
                        detail=detail,
                        latency_ms=round((monotonic() - started) * 1000, 2),
                    )
                )

        ready = all(check.status == "ok" for check in checks if check.required)
        return ReadinessReport(status="ready" if ready else "not_ready", checks=tuple(checks))
