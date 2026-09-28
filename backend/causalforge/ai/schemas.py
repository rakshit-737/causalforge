"""Small structured AI output schemas used by the investigation workflow."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class HypothesisProposal(BaseModel):
    """One competing incident explanation proposed by a model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    statement: str = Field(min_length=1, max_length=2000)
    supporting_observation_ids: tuple[UUID, ...] = ()
    required_evidence: tuple[str, ...] = ()
    disconfirming_evidence: tuple[str, ...] = ()
    attack_technique_ids: tuple[str, ...] = ()
    initial_confidence: float = Field(ge=0, le=1)
    risk_if_true: Literal["low", "medium", "high", "critical"]


class HypothesisBatch(BaseModel):
    """Bounded competing hypotheses; an empty list is valid in rule-only mode."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypotheses: tuple[HypothesisProposal, ...] = Field(max_length=8)
    mode: Literal["model_assisted", "rule_only"]
    rationale: str = Field(min_length=1, max_length=2000)
