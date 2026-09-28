"""Immutable evidence item model derived from canonical observations."""

from datetime import datetime
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from causalforge.domain.events import CanonicalEvent, Coverage, SourceRef
from causalforge.domain.serialization import sha256_hex


class EvidenceItem(BaseModel):
    """Provenance-bearing evidence record; raw secret values are never part of this model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    evidence_id: UUID
    case_id: UUID
    tenant_id: UUID
    source: SourceRef
    observed_at: datetime
    collected_at: datetime
    parser_version: str = Field(min_length=1)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    redaction_profile: str = Field(min_length=1)
    coverage: Coverage
    normalized: dict[str, Any]
    raw_reference: str | None = None
    source_reliability: float = Field(ge=0, le=1)
    source_family: str = Field(min_length=1)

    @field_validator("observed_at", "collected_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_normalized_provenance(self) -> "EvidenceItem":
        """Bind the normalized payload to the evidence envelope before workflow use."""

        try:
            event = CanonicalEvent.model_validate(self.normalized)
        except ValidationError as exc:
            raise ValueError("evidence normalized payload is not a canonical event") from exc
        if event.tenant_id != self.tenant_id:
            raise ValueError("evidence tenant does not match its normalized event")
        if self.content_hash_for(self.normalized) != self.content_hash:
            raise ValueError("evidence content hash does not match its normalized event")
        return self

    @classmethod
    def from_event(
        cls,
        event: CanonicalEvent,
        *,
        case_id: UUID,
        collected_at: datetime,
        redaction_profile: str,
        source_reliability: float,
        source_family: str,
        evidence_id: UUID | None = None,
    ) -> "EvidenceItem":
        normalized = event.canonical_payload()
        content_hash = cls.content_hash_for(normalized)
        return cls(
            schema_version="1.0",
            evidence_id=evidence_id
            or uuid5(NAMESPACE_URL, f"causalforge:evidence:{case_id}:{content_hash}"),
            case_id=case_id,
            tenant_id=event.tenant_id,
            source=event.source,
            observed_at=event.observed_at,
            collected_at=collected_at,
            parser_version=event.parser_version,
            content_hash=content_hash,
            redaction_profile=redaction_profile,
            coverage=event.coverage,
            normalized=normalized,
            source_reliability=source_reliability,
            source_family=source_family,
        )

    @staticmethod
    def content_hash_for(normalized: dict[str, Any]) -> str:
        """Hash stable observation content while excluding server receipt time."""

        stable = dict(normalized)
        stable.pop("ingested_at", None)
        return sha256_hex(stable)
