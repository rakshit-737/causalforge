"""Tenant-scoped canonical event repository."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.domain.events import CanonicalEvent
from causalforge.ingestion.deduplication import deduplication_key
from causalforge.storage.models.event import EventRecord


class EventRepository:
    """Persist canonical events with database-backed duplicate suppression."""

    def append(self, session: Session, *, event: CanonicalEvent) -> tuple[EventRecord, bool]:
        key = deduplication_key(event)
        existing = session.scalar(
            select(EventRecord).where(
                EventRecord.tenant_id == str(event.tenant_id),
                EventRecord.deduplication_key == key,
            )
        )
        if existing is not None:
            return existing, False
        record = EventRecord.from_event(event)
        session.add(record)
        session.flush()
        return record, True
