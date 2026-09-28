"""Persisted deterministic detection result."""

from datetime import datetime

from sqlalchemy import JSON, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.detection.sigma_engine import DetectionMatch
from causalforge.storage.models.base import Base, UTCDateTime


class DetectionRecord(Base):
    """One rule/event match scoped to an incident and tenant."""

    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "rule_id",
            "event_id",
            name="uq_detections_incident_rule_event",
        ),
        Index("ix_detections_tenant_incident", "tenant_id", "incident_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(160), nullable=False)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    explanation: Mapped[str] = mapped_column(String(2000), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    @classmethod
    def from_match(
        cls,
        match: DetectionMatch,
        *,
        tenant_id: str,
        incident_id: str,
        detected_at: datetime,
        record_id: str,
    ) -> "DetectionRecord":
        """Map an engine match to a persistence row."""

        return cls(
            id=record_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            rule_id=match.rule_id,
            event_id=match.event_id,
            title=match.title,
            level=match.level,
            tags=list(match.tags),
            explanation=match.explanation,
            detected_at=detected_at,
        )
