"""Immutable evidence item model derived from canonical observations."""

from datetime import UTC, datetime
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
    provenance_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
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
        if (
            event.source != self.source
            or event.observed_at != self.observed_at
            or event.parser_version != self.parser_version
            or event.coverage != self.coverage
        ):
            raise ValueError("evidence provenance metadata does not match its normalized event")
        if self.content_hash_for(self.normalized) != self.content_hash:
            raise ValueError("evidence content hash does not match its normalized event")
        expected_provenance_hash = self.provenance_hash_for(
            evidence_id=self.evidence_id,
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            source=self.source,
            observed_at=self.observed_at,
            collected_at=self.collected_at,
            parser_version=self.parser_version,
            content_hash=self.content_hash,
            redaction_profile=self.redaction_profile,
            coverage=self.coverage,
            raw_reference=self.raw_reference,
            source_reliability=self.source_reliability,
            source_family=self.source_family,
        )
        if expected_provenance_hash != self.provenance_hash:
            raise ValueError("evidence provenance hash does not match its immutable envelope")
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
        resolved_evidence_id = evidence_id or uuid5(
            NAMESPACE_URL, f"causalforge:evidence:{case_id}:{content_hash}"
        )
        provenance_hash = cls.provenance_hash_for(
            evidence_id=resolved_evidence_id,
            case_id=case_id,
            tenant_id=event.tenant_id,
            source=event.source,
            observed_at=event.observed_at,
            collected_at=collected_at,
            parser_version=event.parser_version,
            content_hash=content_hash,
            redaction_profile=redaction_profile,
            coverage=event.coverage,
            raw_reference=None,
            source_reliability=source_reliability,
            source_family=source_family,
        )
        return cls(
            schema_version="1.0",
            evidence_id=resolved_evidence_id,
            case_id=case_id,
            tenant_id=event.tenant_id,
            source=event.source,
            observed_at=event.observed_at,
            collected_at=collected_at,
            parser_version=event.parser_version,
            content_hash=content_hash,
            provenance_hash=provenance_hash,
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

    @staticmethod
    def provenance_hash_for(
        *,
        evidence_id: UUID,
        case_id: UUID,
        tenant_id: UUID,
        source: SourceRef,
        observed_at: datetime,
        collected_at: datetime,
        parser_version: str,
        content_hash: str,
        redaction_profile: str,
        coverage: Coverage,
        raw_reference: str | None,
        source_reliability: float,
        source_family: str,
    ) -> str:
        """Hash the immutable evidence envelope, including scope and collection metadata."""

        return sha256_hex(
            {
                "evidence_id": str(evidence_id),
                "case_id": str(case_id),
                "tenant_id": str(tenant_id),
                "source": source.model_dump(mode="json"),
                "observed_at": observed_at.astimezone(UTC).isoformat(),
                "collected_at": collected_at.astimezone(UTC).isoformat(),
                "parser_version": parser_version,
                "content_hash": content_hash,
                "redaction_profile": redaction_profile,
                "coverage": coverage.model_copy(update={
                    "window_start": coverage.window_start.astimezone(UTC),
                    "window_end": coverage.window_end.astimezone(UTC),
                }).model_dump(mode="json"),
                "raw_reference": raw_reference,
                "source_reliability": source_reliability,
                "source_family": source_family,
            }
        )
