from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from causalforge.audit.ledger import AuditLedger
from causalforge.ingestion.service import IngestionService
from causalforge.storage.db import Database
from causalforge.storage.models.audit import AuditEntryRecord
from causalforge.storage.models.event import EventRecord
from causalforge.storage.models.evidence import EvidenceRecord
from causalforge.storage.repositories.evidence import EvidenceRepository


def event_payload(tenant_id: UUID) -> dict[str, object]:
    return {
        "event_id": str(uuid4()),
        "tenant_id": str(tenant_id),
        "source": {"kind": "kubernetes_audit", "name": "fixture", "version": "1.0"},
        "observed_at": "2026-09-28T10:03:00Z",
        "actor": {"kind": "service_account", "id": "system:serviceaccount:orders:reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {"request_uri": "/api/v1/namespaces/orders/secrets", "token": "not-stored"},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-28T10:00:00Z",
            "window_end": "2026-09-28T10:05:00Z",
        },
    }


def test_ingestion_persists_redacted_event_evidence_and_audit_chain(tmp_path) -> None:
    tenant_id = uuid4()
    case_id = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'ingestion.db'}")
    database.create_schema()
    service = IngestionService()
    collected_at = datetime(2026, 9, 28, 10, 3, 1, tzinfo=UTC)

    with database.session() as session:
        first = service.ingest(
            session,
            payload=event_payload(tenant_id),
            case_id=case_id,
            parser_version="fixture-1.0",
            collected_at=collected_at,
        )
        session.commit()

        assert first.duplicate is False
        assert first.evidence_record is not None
        assert service.audit.verify(session, tenant_id=tenant_id, case_id=case_id) is True
        assert session.scalar(select(EventRecord.canonical_payload)) is not None
        assert session.scalar(select(EvidenceRecord.normalized)) is not None

        event = session.scalar(select(EventRecord))
        evidence = session.scalar(select(EvidenceRecord))
        audit = session.scalar(select(AuditEntryRecord))

    assert event is not None
    assert evidence is not None
    assert audit is not None
    assert "not-stored" not in str(event.canonical_payload)
    assert "not-stored" not in str(evidence.normalized)
    assert audit.sequence == 1
    assert audit.previous_entry_hash == "0" * 64


def test_ingestion_is_idempotent_for_duplicate_payload(tmp_path) -> None:
    tenant_id = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'duplicate.db'}")
    database.create_schema()
    service = IngestionService()
    raw = event_payload(tenant_id)

    with database.session() as session:
        first_case = uuid4()
        second_case = uuid4()
        first = service.ingest(
            session, payload=raw, case_id=first_case, parser_version="fixture-1.0"
        )
        session.commit()
        second = service.ingest(
            session, payload=raw, case_id=second_case, parser_version="fixture-1.0"
        )
        session.commit()

        assert first.duplicate is False
        assert second.duplicate is True
        assert second.evidence_record is not None
        assert session.scalar(select(EventRecord)) is not None
        assert len(list(session.scalars(select(EventRecord)))) == 1
        assert len(list(session.scalars(select(EvidenceRecord)))) == 2
        assert {
            record.case_id for record in session.scalars(select(EvidenceRecord))
        } == {str(first_case), str(second_case)}
        assert len(list(session.scalars(select(AuditEntryRecord)))) == 2


def test_audit_chain_detects_tampering(tmp_path) -> None:
    tenant_id = uuid4()
    case_id = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'audit.db'}")
    database.create_schema()
    ledger = AuditLedger()

    with database.session() as session:
        ledger.append(
            session,
            tenant_id=tenant_id,
            case_id=case_id,
            actor={"kind": "test", "id": "fixture", "role": "system"},
            event_type="test.one",
            payload={"value": 1},
            policy_decision="allow",
        )
        ledger.append(
            session,
            tenant_id=tenant_id,
            case_id=case_id,
            actor={"kind": "test", "id": "fixture", "role": "system"},
            event_type="test.two",
            payload={"value": 2},
            policy_decision="allow",
        )
        session.commit()
        assert ledger.verify(session, tenant_id=tenant_id, case_id=case_id) is True

        row = session.scalar(select(AuditEntryRecord).where(AuditEntryRecord.sequence == 2))
        assert row is not None
        row.entry_hash = "f" * 64
        assert ledger.verify(session, tenant_id=tenant_id, case_id=case_id) is False


def test_evidence_integrity_check_detects_normalized_payload_tampering(tmp_path) -> None:
    tenant_id = uuid4()
    case_id = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'evidence-integrity.db'}")
    database.create_schema()
    service = IngestionService()

    with database.session() as session:
        result = service.ingest(
            session,
            payload=event_payload(tenant_id),
            case_id=case_id,
            parser_version="fixture-1.0",
        )
        session.commit()
        assert result.evidence_record is not None
        result.evidence_record.normalized["action"] = "tampered"

        with pytest.raises(ValueError, match="content hash"):
            EvidenceRepository.verify_integrity(result.evidence_record)


def test_same_producer_event_id_can_exist_in_two_tenants(tmp_path) -> None:
    tenant_a = uuid4()
    tenant_b = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'event-identity.db'}")
    database.create_schema()
    service = IngestionService()
    producer_event_id = str(uuid4())
    raw_a = event_payload(tenant_a)
    raw_b = event_payload(tenant_b)
    raw_a["event_id"] = producer_event_id
    raw_b["event_id"] = producer_event_id

    with database.session() as session:
        first = service.ingest(
            session, payload=raw_a, case_id=uuid4(), parser_version="fixture-1.0"
        )
        second = service.ingest(
            session, payload=raw_b, case_id=uuid4(), parser_version="fixture-1.0"
        )
        session.commit()

    assert first.event_record.id != second.event_record.id
    assert first.event_record.producer_event_id == producer_event_id
    assert second.event_record.producer_event_id == producer_event_id
