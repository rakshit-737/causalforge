"""Persisted evidence-bound claim."""

from datetime import datetime

from sqlalchemy import JSON, Boolean, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.domain.claims import Claim
from causalforge.storage.models.base import Base, UTCDateTime


class ClaimRecord(Base):
    """Claim row retaining status, confidence components, and evidence references."""

    __tablename__ = "claims"
    __table_args__ = (
        Index("ix_claims_tenant_incident_status", "tenant_id", "incident_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    predicate: Mapped[str] = mapped_column(String(255), nullable=False)
    object_value: Mapped[dict[str, object] | str | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    supporting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradictory_evidence_ids: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    confidence_components: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False)
    temporal_consistency: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source_families: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    coverage_sufficient: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    @classmethod
    def from_claim(cls, claim: Claim, *, created_at: datetime) -> "ClaimRecord":
        """Map a validated claim to a persistence row."""

        return cls(
            id=str(claim.claim_id),
            tenant_id=str(claim.tenant_id),
            incident_id=str(claim.case_id),
            subject=claim.subject,
            predicate=claim.predicate,
            object_value=claim.object,
            status=claim.status,
            supporting_evidence_ids=[str(value) for value in claim.supporting_evidence_ids],
            contradictory_evidence_ids=[str(value) for value in claim.contradictory_evidence_ids],
            confidence_components=claim.confidence_components.model_dump(),
            temporal_consistency=claim.temporal_consistency,
            source_families=list(claim.source_families),
            coverage_sufficient=claim.coverage_sufficient,
            created_at=created_at,
        )
