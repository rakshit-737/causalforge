"""Minimal incident/case persistence model for the deterministic engine."""

from datetime import datetime

from sqlalchemy import Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.storage.models.base import Base, UTCDateTime, utc_now


class IncidentRecord(Base):
    """Tenant-scoped incident identity and lifecycle checkpoint."""

    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_tenant_status", "tenant_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="NEW")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
