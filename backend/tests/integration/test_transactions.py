"""Real SQLite rollback and concurrent-writer regression tests (no mocked commits)."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from lab.simulator.scenario import TENANT_ID, compromised_orders_workload
from sqlalchemy import select

from causalforge.audit.ledger import AuditLedger
from causalforge.ingestion.service import IngestionService
from causalforge.storage.db import Database
from causalforge.storage.models import AuditEntryRecord, EventRecord, EvidenceRecord


def test_released_savepoints_never_commit_an_aborted_outer_transaction(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'rollback.db'}")
    database.create_schema()
    service = IngestionService()
    payload = compromised_orders_workload()[0][0]
    try:
        with pytest.raises(RuntimeError, match="abort batch"):
            with database.session() as session:
                service.ingest(
                    session,
                    payload=payload,
                    case_id=uuid4(),
                    parser_version="fixture-1",
                )
                raise RuntimeError("abort batch after all savepoints have been released")
        with database.session() as session:
            assert list(session.scalars(select(EventRecord))) == []
            assert list(session.scalars(select(EvidenceRecord))) == []
            assert list(session.scalars(select(AuditEntryRecord))) == []
    finally:
        database.dispose()


@pytest.mark.parametrize("identical", [True, False])
def test_concurrent_ingestion_preserves_one_evidence_lineage_and_audit_chain(
    tmp_path, identical
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'concurrency.db'}")
    database.create_schema()
    case_id = uuid4()
    payload = compromised_orders_workload()[0][0]
    barrier = Barrier(4)

    def worker(index):
        raw = dict(payload)
        if not identical:
            raw["event_id"] = str(uuid4())
            raw["action"] = f"fixture-{index}"
        barrier.wait(timeout=10)
        with database.session() as session:
            result = IngestionService().ingest(
                session, payload=raw, case_id=case_id, parser_version="fixture-1"
            )
            session.commit()
            return result.duplicate

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            duplicate_flags = list(pool.map(worker, range(4)))
        expected = 1 if identical else 4
        with database.session() as session:
            assert len(list(session.scalars(select(EventRecord)))) == expected
            assert len(list(session.scalars(select(EvidenceRecord)))) == expected
            assert len(list(session.scalars(select(AuditEntryRecord)))) == expected
            assert AuditLedger().verify(session, tenant_id=TENANT_ID, case_id=case_id)
        assert sum(duplicate_flags) == (3 if identical else 0)
    finally:
        database.dispose()
