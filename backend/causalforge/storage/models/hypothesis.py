"""Durable tenant-scoped hypothesis and verification attempt records."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.domain.hypotheses import Hypothesis, RiskAssessment
from causalforge.storage.models.base import Base, UTCDateTime, new_id, utc_now
from causalforge.workflow.verifier import VerificationDecision, VerificationPolicy


class HypothesisRecord(Base):
    """Persisted competing hypothesis; status is never inferred from model confidence."""

    __tablename__ = "hypotheses"
    __table_args__ = (
        Index("ix_hypotheses_tenant_incident_status", "tenant_id", "incident_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    statement: Mapped[str] = mapped_column(String(2000), nullable=False)
    supporting_observation_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    disconfirming_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    attack_technique_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    initial_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_if_true: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    @classmethod
    def from_hypothesis(cls, hypothesis: Hypothesis) -> "HypothesisRecord":
        """Map a validated domain hypothesis to durable storage."""

        return cls(
            id=str(hypothesis.hypothesis_id),
            tenant_id=str(hypothesis.tenant_id),
            incident_id=str(hypothesis.case_id),
            statement=hypothesis.statement,
            supporting_observation_ids=[
                str(value) for value in hypothesis.supporting_observation_ids
            ],
            required_evidence=list(hypothesis.required_evidence),
            disconfirming_evidence=list(hypothesis.disconfirming_evidence),
            attack_technique_ids=list(hypothesis.attack_technique_ids),
            initial_confidence=hypothesis.initial_confidence,
            risk_if_true=hypothesis.risk_if_true.model_dump(),
            status=hypothesis.status,
        )

    def to_hypothesis(self) -> Hypothesis:
        """Revalidate a persisted row before it enters workflow code."""

        return Hypothesis(
            schema_version="1.0",
            hypothesis_id=UUID(self.id),
            case_id=UUID(self.incident_id),
            tenant_id=UUID(self.tenant_id),
            statement=self.statement,
            supporting_observation_ids=tuple(
                UUID(value) for value in self.supporting_observation_ids
            ),
            required_evidence=tuple(self.required_evidence),
            disconfirming_evidence=tuple(self.disconfirming_evidence),
            attack_technique_ids=tuple(self.attack_technique_ids),
            initial_confidence=self.initial_confidence,
            risk_if_true=RiskAssessment.model_validate(self.risk_if_true),
            status=self.status,  # type: ignore[arg-type]
        )


class VerificationRecord(Base):
    """Immutable result of one bounded hypothesis verification attempt."""

    __tablename__ = "verification_records"
    __table_args__ = (
        Index(
            "ix_verification_tenant_incident_hypothesis",
            "tenant_id",
            "incident_id",
            "hypothesis_id",
            "checked_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    supporting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    source_families: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    coverage_sufficient: Mapped[bool] = mapped_column(Boolean, nullable=False)
    temporal_consistency: Mapped[bool] = mapped_column(Boolean, nullable=False)
    unmet_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    consumed_evidence_items: Mapped[int] = mapped_column(Integer, nullable=False)
    budget_exhausted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    policy: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)

    @classmethod
    def from_decision(
        cls,
        decision: VerificationDecision,
        *,
        tenant_id: UUID,
        case_id: UUID,
        policy: VerificationPolicy,
    ) -> "VerificationRecord":
        """Map a validated verification decision to an immutable row."""

        return cls(
            tenant_id=str(tenant_id),
            incident_id=str(case_id),
            hypothesis_id=str(decision.hypothesis_id),
            status=decision.status,
            supporting_evidence_ids=[str(value) for value in decision.supporting_evidence_ids],
            source_families=list(decision.source_families),
            coverage_sufficient=decision.coverage_sufficient,
            temporal_consistency=decision.temporal_consistency,
            unmet_requirements=list(decision.unmet_requirements),
            reason=decision.reason,
            checked_at=decision.checked_at,
            consumed_evidence_items=decision.consumed_evidence_items,
            budget_exhausted=decision.budget_exhausted,
            policy=policy.model_dump(mode="json"),
        )
