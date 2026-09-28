"""Durable ingestion service for normalized events and evidence."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from causalforge.audit.ledger import AuditLedger
from causalforge.domain.evidence import EvidenceItem
from causalforge.ingestion.normalizer import NormalizedEvent, normalize_event
from causalforge.storage.models.event import EventRecord
from causalforge.storage.models.evidence import EvidenceRecord
from causalforge.storage.repositories.events import EventRepository
from causalforge.storage.repositories.evidence import EvidenceRepository


@dataclass(frozen=True)
class IngestResult:
    """Result of one idempotent ingestion attempt."""

    normalized: NormalizedEvent
    event_record: EventRecord
    evidence_record: EvidenceRecord | None
    duplicate: bool


class IngestionService:
    """Normalize, deduplicate, persist, and audit one case-scoped observation."""

    def __init__(
        self,
        *,
        event_repository: EventRepository | None = None,
        evidence_repository: EvidenceRepository | None = None,
        audit_ledger: AuditLedger | None = None,
    ) -> None:
        self.events = event_repository or EventRepository()
        self.evidence = evidence_repository or EvidenceRepository()
        self.audit = audit_ledger or AuditLedger()

    def ingest(
        self,
        session: Session,
        *,
        payload: Mapping[str, Any],
        case_id: UUID,
        expected_tenant_id: UUID | None = None,
        parser_version: str,
        collected_at: datetime | None = None,
        source_reliability: float = 1.0,
        source_family: str | None = None,
        redaction_profile: str = "default-v1",
        actor: Mapping[str, str] | None = None,
    ) -> IngestResult:
        normalized = normalize_event(payload, parser_version=parser_version)
        if expected_tenant_id is not None and normalized.event.tenant_id != expected_tenant_id:
            raise ValueError("event tenant does not match the requested case tenant")
        event_record, inserted = self.events.append(session, event=normalized.event)
        if not inserted:
            # Deduplication intentionally ignores producer IDs and receipt metadata. Replays must
            # attach the already-persisted canonical observation, not create a second evidence
            # lineage from a semantically identical but differently identified payload.
            normalized = NormalizedEvent(
                event=event_record.to_event(),
                redaction=normalized.redaction,
            )
        collected = collected_at or datetime.now(UTC)
        evidence = EvidenceItem.from_event(
            normalized.event,
            case_id=case_id,
            collected_at=collected,
            redaction_profile=redaction_profile,
            source_reliability=source_reliability,
            source_family=source_family or normalized.event.source.kind,
        )
        evidence_record, evidence_inserted = self.evidence.append(session, evidence=evidence)
        if evidence_inserted:
            self.audit.append(
                session,
                tenant_id=normalized.event.tenant_id,
                case_id=case_id,
                actor=actor
                or {
                    "kind": "connector",
                    "id": normalized.event.source.name,
                    "role": "ingest",
                },
                event_type="evidence.ingested",
                payload={
                    "event_id": str(normalized.event.event_id),
                    "evidence_id": str(evidence_record.id),
                    "content_hash": evidence_record.content_hash,
                    "redacted_paths": list(normalized.redaction.paths),
                },
                policy_decision="allow",
                created_at=collected,
            )
        return IngestResult(
            normalized=normalized,
            event_record=event_record,
            evidence_record=evidence_record,
            duplicate=not inserted,
        )
