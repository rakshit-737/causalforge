"""Versioned API request and response contracts."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from causalforge.domain.hypotheses import RiskAssessment


class EventIngestRequest(BaseModel):
    """One event submission bound to an incident case."""

    model_config = ConfigDict(extra="forbid")

    case_id: UUID
    parser_version: str = Field(min_length=1, max_length=120)
    event: dict[str, Any]
    title: str = Field(default="API security investigation", min_length=1, max_length=255)


class EventBatchIngestRequest(BaseModel):
    """Bounded batch submission for deterministic replay."""

    model_config = ConfigDict(extra="forbid")

    case_id: UUID
    parser_version: str = Field(min_length=1, max_length=120)
    events: list[dict[str, Any]] = Field(min_length=1, max_length=100)
    title: str = Field(default="API security investigation", min_length=1, max_length=255)


class InvestigationRequest(EventBatchIngestRequest):
    """Investigation request; kept separate for future planner inputs."""


class EventResponse(BaseModel):
    """Safe redacted event response."""

    model_config = ConfigDict(frozen=True)

    event_id: UUID
    tenant_id: UUID
    observed_at: datetime
    ingested_at: datetime
    source_kind: str
    source_name: str
    actor_kind: str
    actor_id: str
    action: str
    object_kind: str
    object_namespace: str | None
    object_name: str | None
    outcome: str
    attributes: dict[str, Any]
    raw_payload_sha256: str
    parser_version: str


class EvidenceResponse(BaseModel):
    """Provenance-only evidence response with normalized redacted data."""

    model_config = ConfigDict(frozen=True)

    evidence_id: UUID
    case_id: UUID
    tenant_id: UUID
    source_kind: str
    source_name: str
    observed_at: datetime
    collected_at: datetime
    content_hash: str
    redaction_profile: str
    normalized: dict[str, Any]
    source_reliability: float
    source_family: str


class ClaimResponse(BaseModel):
    """Claim response with explicit state and evidence IDs."""

    model_config = ConfigDict(frozen=True)

    claim_id: UUID
    case_id: UUID
    tenant_id: UUID
    subject: str
    predicate: str
    object: dict[str, Any] | str | None
    status: str
    supporting_evidence_ids: list[UUID]
    contradictory_evidence_ids: list[UUID]
    confidence_components: dict[str, float]
    coverage_sufficient: bool


class HypothesisCreateRequest(BaseModel):
    """Create one bounded competing explanation without choosing its final status."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: UUID | None = None
    statement: str = Field(min_length=1, max_length=2000)
    supporting_observation_ids: list[UUID] = Field(default_factory=list, max_length=100)
    required_evidence: list[str] = Field(default_factory=list, max_length=50)
    disconfirming_evidence: list[str] = Field(default_factory=list, max_length=50)
    attack_technique_ids: list[str] = Field(default_factory=list, max_length=20)
    initial_confidence: float = Field(ge=0, le=1)
    risk_if_true: RiskAssessment

    @field_validator("supporting_observation_ids", "attack_technique_ids")
    @classmethod
    def require_unique_references(cls, value: list[UUID] | list[str]) -> list[UUID] | list[str]:
        if len(value) != len(set(value)):
            raise ValueError("hypothesis references must be unique")
        return value


class HypothesisResponse(BaseModel):
    """Persisted hypothesis with explicit workflow status."""

    model_config = ConfigDict(frozen=True)

    hypothesis_id: UUID
    case_id: UUID
    tenant_id: UUID
    statement: str
    supporting_observation_ids: list[UUID]
    required_evidence: list[str]
    disconfirming_evidence: list[str]
    attack_technique_ids: list[str]
    initial_confidence: float
    risk_if_true: RiskAssessment
    status: str
    created_at: datetime
    updated_at: datetime
    version: int


class VerificationRequest(BaseModel):
    """Bound the deterministic verification attempt supplied by an analyst."""

    model_config = ConfigDict(extra="forbid")

    minimum_independent_source_families: int = Field(default=2, ge=1, le=20)
    require_complete_coverage: bool = True
    max_evidence_items: int = Field(default=100, ge=1, le=10_000)
    deadline: datetime | None = None

    @field_validator("deadline")
    @classmethod
    def require_deadline_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("verification deadline must be timezone-aware")
        return value


class VerificationResponse(BaseModel):
    """Durable result of one fail-closed verification attempt."""

    model_config = ConfigDict(frozen=True)

    verification_id: UUID
    hypothesis_id: UUID
    status: str
    supporting_evidence_ids: list[UUID]
    source_families: list[str]
    coverage_sufficient: bool
    temporal_consistency: bool
    unmet_requirements: list[str]
    reason: str
    checked_at: datetime
    consumed_evidence_items: int
    budget_exhausted: bool


class IncidentResponse(BaseModel):
    """Tenant-scoped incident summary."""

    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    tenant_id: UUID
    status: str
    severity: str
    title: str
    created_at: datetime
    updated_at: datetime
    version: int


class DetectionResponse(BaseModel):
    """Persisted deterministic detection response."""

    model_config = ConfigDict(frozen=True)

    detection_id: UUID
    rule_id: str
    event_id: UUID
    title: str
    level: str
    tags: list[str]
    explanation: str
    detected_at: datetime


class InvestigationResponse(BaseModel):
    """Summary returned after a bounded rule-only investigation run."""

    model_config = ConfigDict(frozen=True)

    incident: IncidentResponse
    ingested_count: int
    duplicate_count: int
    detection_count: int
    claim_count: int
    correlations_count: int
    detections: list[DetectionResponse]


class GraphResponse(BaseModel):
    """JSON-safe temporal graph snapshot."""

    model_config = ConfigDict(frozen=True)

    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    """Stable safe error shape for clients."""

    code: str
    detail: str
