"""Evidence-bound hypothesis contracts for the investigation workflow."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

HypothesisStatus = Literal["proposed", "supported", "rejected", "insufficient_evidence"]


class RiskAssessment(BaseModel):
    """Explicit risk context kept separate from confidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Literal["low", "medium", "high", "critical"]
    rationale: str = Field(min_length=1, max_length=2000)


class Hypothesis(BaseModel):
    """A bounded incident explanation that cannot become fact without verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    hypothesis_id: UUID
    case_id: UUID
    tenant_id: UUID
    statement: str = Field(min_length=1, max_length=2000)
    supporting_observation_ids: tuple[UUID, ...] = ()
    required_evidence: tuple[str, ...] = ()
    disconfirming_evidence: tuple[str, ...] = ()
    attack_technique_ids: tuple[str, ...] = ()
    initial_confidence: float = Field(ge=0, le=1)
    risk_if_true: RiskAssessment
    status: HypothesisStatus

    @field_validator("supporting_observation_ids", "attack_technique_ids")
    @classmethod
    def require_unique_values(
        cls, value: tuple[UUID, ...] | tuple[str, ...]
    ) -> tuple[UUID, ...] | tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("hypothesis references must be unique")
        return value
