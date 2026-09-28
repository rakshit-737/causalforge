"""Fail-closed, evidence-bound hypothesis verification.

This module is deliberately pure: it does not collect evidence, call an LLM, change targets, or
write a database row. A coordinator can persist its decision only after the returned evidence IDs,
coverage assessment, and budget/deadline checks have been audited.
"""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from causalforge.domain.claims import Claim
from causalforge.domain.events import CanonicalEvent
from causalforge.domain.evidence import EvidenceItem
from causalforge.domain.hypotheses import Hypothesis


class VerificationPolicy(BaseModel):
    """Bound the evidence and independence requirements for one verification attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum_independent_source_families: int = Field(default=2, ge=2, le=20, strict=True)
    require_complete_coverage: Literal[True] = True
    max_evidence_items: int = Field(default=100, ge=1, le=10_000)
    deadline: datetime | None = None

    @field_validator("deadline")
    @classmethod
    def require_deadline_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("verification deadline must be timezone-aware")
        return value


VerificationStatus = Literal["insufficient_evidence"]


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


class TrustedSource(BaseModel):
    """Server-owned provenance attestation, never accepted from an API request.

    A caller may supply these only for authenticated collectors or explicitly trusted local
    fixtures. Different labels on submitted telemetry do not establish independence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    independent_family: str = Field(min_length=1)


def _checked_at(now: datetime | None) -> datetime:
    value = now if now is not None else datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("verification clock must be timezone-aware")
    return value.astimezone(UTC)


def _validated_evidence(
    evidence: tuple[EvidenceItem, ...] | list[EvidenceItem],
    *,
    tenant_id: UUID,
    case_id: UUID,
    limit: int,
) -> tuple[EvidenceItem, ...]:
    if any(item.tenant_id != tenant_id or item.case_id != case_id for item in evidence):
        raise ValueError("verification evidence must match the tenant and case")
    # A frozen Pydantic object still contains mutable JSON; model_copy also bypasses validation.
    ordered = sorted(evidence, key=lambda item: (item.observed_at, str(item.evidence_id)))
    return tuple(EvidenceItem.model_validate(item.model_dump()) for item in ordered[:limit])


def _trusted_families(
    evidence: tuple[EvidenceItem, ...], sources: tuple[TrustedSource, ...]
) -> tuple[tuple[str, ...], bool]:
    registry: dict[tuple[str, str, str], str] = {}
    for source in sources:
        key = (source.kind, source.name, source.version)
        if key in registry:
            raise ValueError("duplicate trusted source registration")
        registry[key] = source.independent_family
    families = [
        registry.get((item.source.kind, item.source.name, item.source.version))
        for item in evidence
    ]
    return tuple(sorted({family for family in families if family is not None})), all(families)


def _claim_matches_event(claim: Claim, evidence: EvidenceItem) -> bool:
    """Check the narrow deterministic semantics supported by observed event claims."""

    event = CanonicalEvent.model_validate(evidence.normalized)
    if event.actor.id != claim.subject or f"{event.action} {event.object.kind}" != claim.predicate:
        return False
    if not isinstance(claim.object, dict):
        return claim.object is None
    return all(
        value is None or value == event_object
        for value, event_object in (
            (claim.object.get("kind"), event.object.kind),
            (claim.object.get("namespace"), event.object.namespace),
            (claim.object.get("name"), event.object.name),
        )
    )


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
    source_families: tuple[str, ...] = (),
    consumed_evidence_items: int = 0,
) -> VerificationDecision:
    ordered = tuple(sorted(evidence, key=lambda item: (item.observed_at, str(item.evidence_id))))
    return VerificationDecision(
        hypothesis_id=hypothesis.hypothesis_id,
        status=status,
        supporting_evidence_ids=tuple(item.evidence_id for item in ordered),
        source_families=source_families,
        coverage_sufficient=coverage_sufficient,
        temporal_consistency=temporal_consistency,
        unmet_requirements=unmet_requirements,
        reason=reason,
        checked_at=checked_at,
        consumed_evidence_items=consumed_evidence_items,
        budget_exhausted=budget_exhausted,
    )


def verify_hypothesis(
    hypothesis: Hypothesis,
    evidence: tuple[EvidenceItem, ...] | list[EvidenceItem],
    *,
    policy: VerificationPolicy | None = None,
    now: datetime | None = None,
    trusted_sources: tuple[TrustedSource, ...] = (),
) -> VerificationDecision:
    """Assess references and coverage without pretending to prove a free-text explanation.

    There is no semantic evaluator for arbitrary hypothesis text. Even complete independent
    observations cannot establish its meaning, required evidence, or absence of alternatives.
    All such assessments therefore remain insufficient_evidence.
    """

    effective_policy = policy or VerificationPolicy()
    checked_at = _checked_at(now)

    if effective_policy.deadline is not None and checked_at >= effective_policy.deadline:
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

    budget_exhausted = len(evidence) > effective_policy.max_evidence_items
    bounded_evidence = _validated_evidence(
        evidence,
        tenant_id=hypothesis.tenant_id,
        case_id=hypothesis.case_id,
        limit=effective_policy.max_evidence_items,
    )
    observation_ids = set(hypothesis.supporting_observation_ids)
    supporting = tuple(
        item for item in bounded_evidence
        if UUID(str(item.normalized["event_id"])) in observation_ids
    )
    if not supporting:
        return _decision(
            hypothesis,
            status="insufficient_evidence",
            evidence=(),
            coverage_sufficient=False,
            temporal_consistency=False,
            unmet_requirements=("supporting_observation", "semantic_verification_required"),
            reason="no referenced supporting evidence was available",
            checked_at=checked_at,
            budget_exhausted=budget_exhausted,
            consumed_evidence_items=len(bounded_evidence),
        )

    ordered = tuple(sorted(supporting, key=lambda item: (item.observed_at, str(item.evidence_id))))
    temporal_consistency = all(
        item.coverage.window_start <= item.observed_at <= item.coverage.window_end
        for item in ordered
    )
    coverage_sufficient = all(
        item.coverage.source_complete_for_window for item in ordered
    ) and temporal_consistency
    source_families, trusted = _trusted_families(ordered, trusted_sources)

    unmet: list[str] = ["semantic_verification_required"]
    if hypothesis.required_evidence:
        unmet.append("required_evidence_not_evaluated")
    if hypothesis.disconfirming_evidence:
        unmet.append("alternatives_not_evaluated")
    if not trusted:
        unmet.append("untrusted_source")
    if observation_ids - {UUID(str(item.normalized["event_id"])) for item in ordered}:
        unmet.append("missing_observation_reference")
    if len(source_families) < effective_policy.minimum_independent_source_families:
        unmet.append("independent_source_families")
    if effective_policy.require_complete_coverage and not coverage_sufficient:
        unmet.append("complete_coverage")
    if budget_exhausted:
        unmet.append("evidence_budget")

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
        source_families=source_families,
        consumed_evidence_items=len(bounded_evidence),
    )


ClaimVerificationStatus = Literal["verified", "disputed", "unknown"]


class ClaimVerificationDecision(BaseModel):
    """Deterministic claim promotion result with explicit contradiction handling."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: UUID
    status: ClaimVerificationStatus
    supporting_evidence_ids: tuple[UUID, ...] = ()
    contradictory_evidence_ids: tuple[UUID, ...] = ()
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
            raise ValueError("claim verification timestamp must be timezone-aware")
        return value.astimezone(UTC)


def verify_claim(
    claim: Claim,
    evidence: tuple[EvidenceItem, ...] | list[EvidenceItem],
    *,
    policy: VerificationPolicy | None = None,
    now: datetime | None = None,
    trusted_sources: tuple[TrustedSource, ...] = (),
) -> ClaimVerificationDecision:
    """Promote a claim only when its cited evidence is independent and complete.

    A contradiction always wins over support and produces ``disputed``. Missing coverage,
    insufficient source independence, deadlines, and budgets produce ``unknown`` rather than a
    misleading verified state.
    """

    effective_policy = policy or VerificationPolicy()
    checked_at = _checked_at(now)
    if effective_policy.deadline is not None and checked_at >= effective_policy.deadline:
        return ClaimVerificationDecision(
            claim_id=claim.claim_id,
            status="unknown",
            coverage_sufficient=False,
            temporal_consistency=False,
            unmet_requirements=("verification_deadline",),
            reason="verification deadline has expired",
            checked_at=checked_at,
            consumed_evidence_items=0,
        )

    budget_exhausted = len(evidence) > effective_policy.max_evidence_items
    bounded_evidence = _validated_evidence(
        evidence,
        tenant_id=claim.tenant_id,
        case_id=claim.case_id,
        limit=effective_policy.max_evidence_items,
    )
    supporting_ids = set(claim.supporting_evidence_ids)
    contradictory_ids = set(claim.contradictory_evidence_ids)
    supporting = tuple(item for item in bounded_evidence if item.evidence_id in supporting_ids)
    contradictory = tuple(
        item for item in bounded_evidence if item.evidence_id in contradictory_ids
    )
    ordered_supporting = tuple(
        sorted(supporting, key=lambda item: (item.observed_at, str(item.evidence_id)))
    )
    source_families, trusted = _trusted_families(ordered_supporting, trusted_sources)
    temporal_consistency = all(
        item.coverage.window_start <= item.observed_at <= item.coverage.window_end
        for item in ordered_supporting
    )
    coverage_sufficient = all(
        item.coverage.source_complete_for_window for item in ordered_supporting
    ) and temporal_consistency
    unmet: list[str] = []
    if not ordered_supporting:
        unmet.append("supporting_evidence")
    if claim.status not in {"observed", "derived"}:
        unmet.append("unsupported_claim_status")
    if not all(_claim_matches_event(claim, item) for item in ordered_supporting):
        unmet.append("claim_semantics")
    if not trusted:
        unmet.append("untrusted_source")
    if len(source_families) < effective_policy.minimum_independent_source_families:
        unmet.append("independent_source_families")
    if effective_policy.require_complete_coverage and not coverage_sufficient:
        unmet.append("complete_coverage")
    if budget_exhausted:
        unmet.append("evidence_budget")
    if contradictory:
        return ClaimVerificationDecision(
            claim_id=claim.claim_id,
            status="disputed",
            supporting_evidence_ids=tuple(item.evidence_id for item in ordered_supporting),
            contradictory_evidence_ids=tuple(item.evidence_id for item in contradictory),
            source_families=source_families,
            coverage_sufficient=coverage_sufficient,
            temporal_consistency=temporal_consistency,
            unmet_requirements=("contradictory_evidence", *unmet),
            reason="cited contradictory evidence prevents promotion",
            checked_at=checked_at,
            consumed_evidence_items=len(bounded_evidence),
            budget_exhausted=budget_exhausted,
        )
    if unmet:
        return ClaimVerificationDecision(
            claim_id=claim.claim_id,
            status="unknown",
            supporting_evidence_ids=tuple(item.evidence_id for item in ordered_supporting),
            source_families=source_families,
            coverage_sufficient=coverage_sufficient,
            temporal_consistency=temporal_consistency,
            unmet_requirements=tuple(unmet),
            reason="; ".join(unmet),
            checked_at=checked_at,
            consumed_evidence_items=len(bounded_evidence),
            budget_exhausted=budget_exhausted,
        )
    return ClaimVerificationDecision(
        claim_id=claim.claim_id,
        status="verified",
        supporting_evidence_ids=tuple(item.evidence_id for item in ordered_supporting),
        source_families=source_families,
        coverage_sufficient=coverage_sufficient,
        temporal_consistency=temporal_consistency,
        reason="independent complete observations verify the claim",
        checked_at=checked_at,
        consumed_evidence_items=len(bounded_evidence),
    )
