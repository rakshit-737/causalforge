"""Evidence-bound claim models created by deterministic security services."""

from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field

from causalforge.domain.events import CanonicalEvent

ClaimStatus = Literal[
    "observed",
    "derived",
    "hypothesized",
    "corroborated",
    "verified",
    "disputed",
    "rejected",
    "unknown",
]


class ConfidenceComponents(BaseModel):
    """Inspectable components of a claim confidence score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_reliability: float = Field(ge=0, le=1)
    temporal_consistency: float = Field(ge=0, le=1)
    coverage: float = Field(ge=0, le=1)
    contradiction_penalty: float = Field(ge=0, le=1)
    final: float = Field(ge=0, le=1)


class Claim(BaseModel):
    """A claim whose status is explicit and tied to immutable evidence IDs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    claim_id: UUID
    case_id: UUID
    tenant_id: UUID
    subject: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    object: str | dict[str, Any] | None = None
    status: ClaimStatus
    supporting_evidence_ids: tuple[UUID, ...] = ()
    contradictory_evidence_ids: tuple[UUID, ...] = ()
    confidence_components: ConfidenceComponents
    temporal_consistency: bool
    source_families: tuple[str, ...]
    coverage_sufficient: bool

    @classmethod
    def observed_from_event(
        cls,
        event: CanonicalEvent,
        *,
        case_id: UUID,
        evidence_id: UUID,
        source_reliability: float,
    ) -> "Claim":
        """Create a direct observation claim without promoting it to corroborated or verified."""

        coverage_score = 1.0 if event.coverage.source_complete_for_window else 0.5
        final = min(source_reliability, coverage_score)
        return cls(
            schema_version="1.0",
            claim_id=uuid5(
                NAMESPACE_URL,
                f"causalforge:observed:{case_id}:{evidence_id}:{event.action}:{event.object.kind}",
            ),
            case_id=case_id,
            tenant_id=event.tenant_id,
            subject=event.actor.id,
            predicate=f"{event.action} {event.object.kind}",
            object={
                "kind": event.object.kind,
                "namespace": event.object.namespace,
                "name": event.object.name,
            },
            status="observed",
            supporting_evidence_ids=(evidence_id,),
            confidence_components=ConfidenceComponents(
                source_reliability=source_reliability,
                temporal_consistency=1.0,
                coverage=coverage_score,
                contradiction_penalty=0.0,
                final=final,
            ),
            temporal_consistency=True,
            source_families=(event.source.kind,),
            coverage_sufficient=event.coverage.source_complete_for_window,
        )
