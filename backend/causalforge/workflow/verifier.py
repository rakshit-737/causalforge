"""Fail-closed, evidence-bound hypothesis verification.

This module is deliberately pure: it does not collect evidence, call an LLM, change targets, or
write a database row. A coordinator can persist its decision only after the returned evidence IDs,
coverage assessment, and budget/deadline checks have been audited.
"""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from causalforge.domain.evidence import EvidenceItem
from causalforge.domain.hypotheses import Hypothesis


class VerificationPolicy(BaseModel):
    """Bound the evidence and independence requirements for one verification attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

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


VerificationStatus = Literal["supported", "rejected", "insufficient_evidence"]


class VerificationDecision(BaseModel):
    """Inspectable result of one bounded verification attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: UUID
    status: VerificationStatus
    supporting_evidence_ids: tuple[UUID, ...] = ()
    source_families: tuple[str, ...] = ()
    coverage_sufficient: bool
    temporal_consistency: bool
    unmet_requirements: tuple[str, ...] = ()
    reason: str = Field(min_length=1, max_length=1000)
    checked_at: datetime
    consumed_evidence_items: int = Field(ge=0)
    budget_exhausted: bool = False

    @field_validator("checked_at")
    @classmethod
    def require_checked_at_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verification timestamp must be timezone-aware")
        return value.astimezone(UTC)


def _event_id(evidence: EvidenceItem) -> UUID | None:
    """Read the producer observation ID only after validating its shape."""

    value = evidence.normalized.get("event_id")
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def _decision(
    hypothesis: Hypothesis,
    *,
    status: VerificationStatus,
    evidence: tuple[EvidenceItem, ...],
    coverage_sufficient: bool,
    temporal_consistency: bool,
    unmet_requirements: tuple[str, ...],
    reason: str,
    checked_at: datetime,
    budget_exhausted: bool = False,
) -> VerificationDecision:
    ordered = tuple(sorted(evidence, key=lambda item: (item.observed_at, str(item.evidence_id))))
    return VerificationDecision(
        hypothesis_id=hypothesis.hypothesis_id,
        status=status,
        supporting_evidence_ids=tuple(item.evidence_id for item in ordered),
        source_families=tuple(sorted({item.source_family for item in ordered})),
        coverage_sufficient=coverage_sufficient,
        temporal_consistency=temporal_consistency,
        unmet_requirements=unmet_requirements,
        reason=reason,
        checked_at=checked_at,
        consumed_evidence_items=len(ordered),
        budget_exhausted=budget_exhausted,
    )


def verify_hypothesis(
    hypothesis: Hypothesis,
    evidence: tuple[EvidenceItem, ...] | list[EvidenceItem],
    *,
    policy: VerificationPolicy | None = None,
    now: datetime | None = None,
) -> VerificationDecision:
    """Verify a hypothesis using only explicitly referenced, tenant-scoped evidence.

    One source family is never enough for support under the default policy. Incomplete coverage,
    malformed observation references, expired deadlines, and exhausted budgets all produce an
    explicit ``insufficient_evidence`` result rather than a best-effort promotion.
    """

    effective_policy = policy or VerificationPolicy()
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("verification clock must be timezone-aware")

    if effective_policy.deadline is not None and checked_at > effective_policy.deadline:
        return _decision(
            hypothesis,
            status="insufficient_evidence",
            evidence=(),
            coverage_sufficient=False,
            temporal_consistency=False,
            unmet_requirements=("verification_deadline",),
            reason="verification deadline has expired",
            checked_at=checked_at,
        )

    all_evidence = tuple(evidence)
    if any(
        item.tenant_id != hypothesis.tenant_id or item.case_id != hypothesis.case_id
        for item in all_evidence
    ):
        raise ValueError("verification evidence must match the hypothesis tenant and case")

    budget_exhausted = len(all_evidence) > effective_policy.max_evidence_items
    bounded_evidence = all_evidence[: effective_policy.max_evidence_items]
    observation_ids = set(hypothesis.supporting_observation_ids)
    supporting = tuple(item for item in bounded_evidence if _event_id(item) in observation_ids)
    if not supporting:
        return _decision(
            hypothesis,
            status="insufficient_evidence",
            evidence=(),
            coverage_sufficient=False,
            temporal_consistency=False,
            unmet_requirements=hypothesis.required_evidence or ("supporting_observation",),
            reason="no referenced supporting evidence was available",
            checked_at=checked_at,
            budget_exhausted=budget_exhausted,
        )

    ordered = tuple(sorted(supporting, key=lambda item: (item.observed_at, str(item.evidence_id))))
    temporal_consistency = all(
        item.coverage.window_start <= item.observed_at <= item.coverage.window_end
        for item in ordered
    )
    coverage_sufficient = all(
        item.coverage.source_complete_for_window for item in ordered
    ) and temporal_consistency
    source_families = {item.source_family for item in ordered}

    unmet: list[str] = []
    if len(source_families) < effective_policy.minimum_independent_source_families:
        unmet.append("independent_source_families")
    if effective_policy.require_complete_coverage and not coverage_sufficient:
        unmet.append("complete_coverage")
    if budget_exhausted:
        unmet.append("evidence_budget")

    if unmet:
        return _decision(
            hypothesis,
            status="insufficient_evidence",
            evidence=ordered,
            coverage_sufficient=coverage_sufficient,
            temporal_consistency=temporal_consistency,
            unmet_requirements=tuple(unmet),
            reason="; ".join(unmet),
            checked_at=checked_at,
            budget_exhausted=budget_exhausted,
        )

    return _decision(
        hypothesis,
        status="supported",
        evidence=ordered,
        coverage_sufficient=coverage_sufficient,
        temporal_consistency=temporal_consistency,
        unmet_requirements=(),
        reason="independent complete observations support the hypothesis",
        checked_at=checked_at,
    )
