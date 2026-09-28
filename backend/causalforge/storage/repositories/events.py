"""Tenant-scoped canonical event repository."""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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
        producer_existing = session.scalar(
            select(EventRecord).where(
                EventRecord.tenant_id == str(event.tenant_id),
                EventRecord.producer_event_id == str(event.event_id),
            )
        )
        if producer_existing is not None:
            raise ValueError("producer event_id is already bound to different content")
        record = EventRecord.from_event(event)
        try:
            with session.begin_nested():
                session.add(record)
                session.flush()
        except IntegrityError as exc:
            # Another transaction may have won the same uniqueness race after the preflight read.
            # The savepoint keeps the caller's outer transaction usable for a safe re-read.
            existing = session.scalar(
                select(EventRecord).where(
                    EventRecord.tenant_id == str(event.tenant_id),
                    EventRecord.deduplication_key == key,
                )
            )
            if existing is not None:
                return existing, False
            producer_existing = session.scalar(
                select(EventRecord).where(
                    EventRecord.tenant_id == str(event.tenant_id),
                    EventRecord.producer_event_id == str(event.event_id),
                )
            )
            if producer_existing is not None:
                raise ValueError(
                    "producer event_id is already bound to different content"
                ) from exc
            raise
        return record, True

    def get_for_tenant(
        self, session: Session, *, tenant_id: str, event_id: str
    ) -> EventRecord | None:
        """Fetch one event only inside the requested tenant scope."""

        return session.scalar(
            select(EventRecord).where(
                EventRecord.tenant_id == tenant_id,
                EventRecord.producer_event_id == event_id,
            )
        )

    def list_for_tenant(self, session: Session, *, tenant_id: str) -> list[EventRecord]:
        """List redacted events for a tenant in observed-time order."""

        return list(
            session.scalars(
                select(EventRecord)
                .where(EventRecord.tenant_id == tenant_id)
                .order_by(EventRecord.observed_at.asc(), EventRecord.id.asc())
            )
        )
