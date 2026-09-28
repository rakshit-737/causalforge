"""Versioned API request and response contracts."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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
