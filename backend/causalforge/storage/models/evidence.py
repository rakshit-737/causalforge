"""Evidence ledger persistence model."""

from datetime import datetime

from sqlalchemy import JSON, Boolean, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.domain.evidence import EvidenceItem
from causalforge.storage.models.base import Base, UTCDateTime


class EvidenceRecord(Base):
    """Immutable provenance-bearing evidence row."""

    __tablename__ = "evidence_items"
    __table_args__ = (
        Index("ix_evidence_tenant_case_observed_at", "tenant_id", "case_id", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    source_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    source_name: Mapped[str] = mapped_column(String(200), nullable=False)
    source_version: Mapped[str] = mapped_column(String(80), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(120), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    redaction_profile: Mapped[str] = mapped_column(String(120), nullable=False)
    coverage_complete: Mapped[bool] = mapped_column(Boolean, nullable=False)
    coverage_window_start: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    coverage_window_end: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    normalized: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    raw_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_reliability: Mapped[float] = mapped_column(nullable=False)
    source_family: Mapped[str] = mapped_column(String(120), nullable=False)

    @classmethod
    def from_evidence(cls, evidence: EvidenceItem) -> "EvidenceRecord":
        """Map a validated evidence item to its immutable persistence row."""

        return cls(
            id=str(evidence.evidence_id),
            case_id=str(evidence.case_id),
            tenant_id=str(evidence.tenant_id),
            source_kind=evidence.source.kind,
            source_name=evidence.source.name,
            source_version=evidence.source.version,
            observed_at=evidence.observed_at,
            collected_at=evidence.collected_at,
            parser_version=evidence.parser_version,
            content_hash=evidence.content_hash,
            redaction_profile=evidence.redaction_profile,
            coverage_complete=evidence.coverage.source_complete_for_window,
            coverage_window_start=evidence.coverage.window_start,
            coverage_window_end=evidence.coverage.window_end,
            normalized=evidence.normalized,
            raw_reference=evidence.raw_reference,
            source_reliability=evidence.source_reliability,
            source_family=evidence.source_family,
        )
