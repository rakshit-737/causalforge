"""Tenant- and case-scoped evidence repository."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.domain.events import CanonicalEvent
from causalforge.domain.evidence import EvidenceItem
from causalforge.storage.models.evidence import EvidenceRecord


class EvidenceRepository:
    """Persist and read evidence only with explicit tenant and case scope."""

    def append(
        self, session: Session, *, evidence: EvidenceItem
    ) -> tuple[EvidenceRecord, bool]:
        existing = session.scalar(
            select(EvidenceRecord).where(
                EvidenceRecord.tenant_id == str(evidence.tenant_id),
                EvidenceRecord.case_id == str(evidence.case_id),
                EvidenceRecord.content_hash == evidence.content_hash,
            )
        )
        if existing is not None:
            return existing, False
        record = EvidenceRecord.from_evidence(evidence)
        session.add(record)
        session.flush()
        return record, True

    def list_for_case(
        self, session: Session, *, tenant_id: UUID, case_id: UUID
    ) -> list[EvidenceRecord]:
        statement = (
            select(EvidenceRecord)
            .where(
                EvidenceRecord.tenant_id == str(tenant_id),
                EvidenceRecord.case_id == str(case_id),
            )
            .order_by(EvidenceRecord.observed_at.asc(), EvidenceRecord.id.asc())
        )
        return list(session.scalars(statement))

    @staticmethod
    def verify_integrity(record: EvidenceRecord) -> None:
        """Fail closed when payload or persisted provenance metadata has been tampered with."""

        if EvidenceItem.content_hash_for(record.normalized) != record.content_hash:
            raise ValueError("evidence content hash mismatch")
        try:
            event = CanonicalEvent.model_validate(record.normalized)
        except ValueError as exc:
            raise ValueError("evidence normalized payload is invalid") from exc
        if (
            str(event.tenant_id) != record.tenant_id
            or event.source.kind != record.source_kind
            or event.source.name != record.source_name
            or event.source.version != record.source_version
            or event.observed_at != record.observed_at
            or event.parser_version != record.parser_version
            or event.coverage.source_complete_for_window != record.coverage_complete
            or event.coverage.window_start != record.coverage_window_start
            or event.coverage.window_end != record.coverage_window_end
        ):
            raise ValueError("evidence provenance metadata mismatch")
