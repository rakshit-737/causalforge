"""Durable claim verification attempt records."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, Boolean, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.storage.models.base import Base, UTCDateTime, new_id, utc_now
from causalforge.workflow.verifier import ClaimVerificationDecision, VerificationPolicy


class ClaimVerificationRecord(Base):
    """Immutable result of one bounded claim verification attempt."""

    __tablename__ = "claim_verification_records"
    __table_args__ = (
        Index(
            "ix_claim_verification_tenant_incident_claim",
            "tenant_id",
            "incident_id",
            "claim_id",
            "checked_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    claim_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    supporting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    contradictory_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
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
        decision: ClaimVerificationDecision,
        *,
        tenant_id: UUID,
        case_id: UUID,
        policy: VerificationPolicy,
    ) -> "ClaimVerificationRecord":
        """Map a validated claim decision to an immutable row."""

        return cls(
            tenant_id=str(tenant_id),
            incident_id=str(case_id),
            claim_id=str(decision.claim_id),
            status=decision.status,
            supporting_evidence_ids=[str(value) for value in decision.supporting_evidence_ids],
            contradictory_evidence_ids=[
                str(value) for value in decision.contradictory_evidence_ids
            ],
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
