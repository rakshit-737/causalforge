"""Typed canonical event models.

The models are deliberately strict at the boundary. Normalization happens before model creation,
so a malformed or secret-bearing source cannot silently become an internal event.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SourceRef(BaseModel):
    """Authenticated source metadata for one event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)


class ActorRef(BaseModel):
    """Identity that performed or attempted the observed action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(min_length=1)
    id: str = Field(min_length=1)


class ObjectRef(BaseModel):
    """Target object reference with names optional for collection actions such as list."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(min_length=1)
    namespace: str | None = None
    name: str | None = None
    uid: str | None = None


class Coverage(BaseModel):
    """Declared completeness window for a source observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_complete_for_window: bool
    window_start: datetime
    window_end: datetime

    @field_validator("window_start", "window_end")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("coverage timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_window(self) -> "Coverage":
        if self.window_end < self.window_start:
            raise ValueError("coverage window_end must not precede window_start")
        return self


class CanonicalEvent(BaseModel):
    """Normalized event contract shared by ingestion, detection, and graph projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    event_id: UUID
    tenant_id: UUID
    source: SourceRef
    observed_at: datetime
    ingested_at: datetime
    actor: ActorRef
    action: str = Field(min_length=1)
    object: ObjectRef
    outcome: Literal["allowed", "denied", "error", "unknown"]
    attributes: dict[str, Any] = Field(default_factory=dict)
    coverage: Coverage
    raw_payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    parser_version: str = Field(min_length=1)

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamps must be timezone-aware")
        return value

    def canonical_payload(self) -> dict[str, Any]:
        """Return the redacted, schema-shaped payload used for evidence hashes."""

        return self.model_dump(mode="json")
