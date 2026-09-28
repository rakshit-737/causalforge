"""Canonical event persistence model."""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, Boolean, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.domain.events import CanonicalEvent
from causalforge.ingestion.deduplication import deduplication_key
from causalforge.storage.models.base import Base, UTCDateTime


class EventRecord(Base):
    """Redacted canonical event stored for deterministic replay and detection."""

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "deduplication_key", name="uq_events_tenant_deduplication"),
        UniqueConstraint("tenant_id", "producer_event_id", name="uq_events_tenant_producer_id"),
        Index("ix_events_tenant_observed_at", "tenant_id", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    producer_event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    source_name: Mapped[str] = mapped_column(String(200), nullable=False)
    source_version: Mapped[str] = mapped_column(String(80), nullable=False)
    actor_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(500), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    object_kind: Mapped[str] = mapped_column(String(120), nullable=False)
    object_namespace: Mapped[str | None] = mapped_column(String(255), nullable=True)
    object_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    object_uid: Mapped[str | None] = mapped_column(String(255), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    attributes: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    coverage_complete: Mapped[bool] = mapped_column(Boolean, nullable=False)
    coverage_window_start: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    coverage_window_end: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    raw_payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(120), nullable=False)
    deduplication_key: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)

    @classmethod
    def from_event(cls, event: CanonicalEvent) -> "EventRecord":
        """Map a canonical event to a redacted persistence row."""

        return cls(
            id=str(uuid4()),
            producer_event_id=str(event.event_id),
            tenant_id=str(event.tenant_id),
            observed_at=event.observed_at,
            ingested_at=event.ingested_at,
            source_kind=event.source.kind,
            source_name=event.source.name,
            source_version=event.source.version,
            actor_kind=event.actor.kind,
            actor_id=event.actor.id,
            action=event.action,
            object_kind=event.object.kind,
            object_namespace=event.object.namespace,
            object_name=event.object.name,
            object_uid=event.object.uid,
            outcome=event.outcome,
            attributes=event.attributes,
            coverage_complete=event.coverage.source_complete_for_window,
            coverage_window_start=event.coverage.window_start,
            coverage_window_end=event.coverage.window_end,
            raw_payload_sha256=event.raw_payload_sha256,
            parser_version=event.parser_version,
            deduplication_key=deduplication_key(event),
            canonical_payload=event.canonical_payload(),
        )

    def to_event(self) -> CanonicalEvent:
        """Revalidate the persisted canonical payload before replay use."""

        return CanonicalEvent.model_validate(self.canonical_payload)
