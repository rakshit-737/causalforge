"""Real SQLite rollback and concurrent-writer regression tests (no mocked commits)."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from lab.simulator.scenario import TENANT_ID, compromised_orders_workload
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from causalforge.audit.ledger import AuditLedger
from causalforge.domain.hypotheses import Hypothesis, RiskAssessment
from causalforge.ingestion.service import IngestionService
from causalforge.storage.db import Database
from causalforge.storage.models import (
    AuditEntryRecord,
    CollectionReceiptRecord,
    EventRecord,
    EvidenceRecord,
    HypothesisRecord,
    IncidentRecord,
    Tenant,
    WorkflowRunRecord,
)
from causalforge.workflow.service import DurableFixtureWorkflow


def _fixture_payload(tenant_id: str) -> dict[str, object]:
    return {
        "event_id": str(uuid4()),
        "tenant_id": tenant_id,
        "source": {"kind": "fixture", "name": "local-fixture", "version": "1.0"},
        "observed_at": "2026-09-30T10:00:00Z",
        "actor": {"kind": "service_account", "id": "orders-reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {"workload_id": "orders-api"},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-30T09:55:00Z",
            "window_end": "2026-09-30T10:05:00Z",
        },
    }


def _workflow_target(database: Database) -> tuple[str, Hypothesis, dict[str, object]]:
    tenant = Tenant(name=f"workflow-{uuid4()}")
    case_id = uuid4()
    hypothesis = Hypothesis(
        schema_version="1.0",
        hypothesis_id=uuid4(),
        case_id=case_id,
        tenant_id=UUID(tenant.id) if tenant.id else uuid4(),
        statement="the fixture reader listed a secret",
        required_evidence=("fixture event replay",),
        risk_if_true=RiskAssessment(severity="high", rationale="test fixture"),
        initial_confidence=0.5,
        status="proposed",
    )
    with database.session() as session:
        session.add(tenant)
        session.flush()
        hypothesis = hypothesis.model_copy(update={"tenant_id": UUID(tenant.id)})
        session.add(
            IncidentRecord(
                id=str(case_id),
                tenant_id=tenant.id,
                status="NEW",
                severity="medium",
                title="Workflow transaction fixture",
            )
        )
        session.add(HypothesisRecord.from_hypothesis(hypothesis))
        session.commit()
    return tenant.id, hypothesis, _fixture_payload(tenant.id)


class _FailingIngestion(IngestionService):
    def ingest_canonical(
        self,
        session: Session,
        *,
        event,
        case_id,
        expected_tenant_id=None,
        collected_at=None,
        source_reliability=1.0,
        source_family=None,
        redaction_profile="default-v1",
        redacted_paths=(),
        actor=None,
    ):
        result = super().ingest_canonical(
            session,
            event=event,
            case_id=case_id,
            expected_tenant_id=expected_tenant_id,
            collected_at=collected_at,
            source_reliability=source_reliability,
            source_family=source_family,
            redaction_profile=redaction_profile,
            redacted_paths=redacted_paths,
            actor=actor,
        )
        del result
        raise RuntimeError("forced workflow failure")


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


def test_durable_workflow_rolls_back_collection_and_audit_artifacts(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'workflow-rollback.db'}")
    database.create_schema()
    tenant_id, hypothesis, payload = _workflow_target(database)
    try:
        with pytest.raises(RuntimeError, match="forced workflow failure"):
            with database.session() as session:
                DurableFixtureWorkflow(ingestion=_FailingIngestion()).execute(
                    session,
                    hypothesis=hypothesis,
                    payloads=[payload],
                    parser_version="fixture-1.0",
                    idempotency_key="rollback-run",
                    actor={"kind": "test", "id": "rollback", "role": "system"},
                )

        with database.session() as session:
            for model in (
                WorkflowRunRecord,
                CollectionReceiptRecord,
                EventRecord,
                EvidenceRecord,
                AuditEntryRecord,
            ):
                assert session.scalar(select(func.count()).select_from(model)) == 0
            assert session.get(IncidentRecord, str(hypothesis.case_id)) is not None
            assert tenant_id
    finally:
        database.dispose()


def test_concurrent_workflow_replay_keeps_one_durable_run(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'workflow-concurrency.db'}")
    database.create_schema()
    tenant_id, hypothesis, payload = _workflow_target(database)
    barrier = Barrier(2)

    def worker() -> tuple[str, bool]:
        barrier.wait(timeout=10)
        with database.session() as session:
            result = DurableFixtureWorkflow().execute(
                session,
                hypothesis=hypothesis,
                payloads=[payload],
                parser_version="fixture-1.0",
                idempotency_key="same-run",
                actor={"kind": "test", "id": "concurrency", "role": "system"},
            )
            session.commit()
            return str(result.run.id), result.replayed

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: worker(), range(2)))
        assert len({run_id for run_id, _ in results}) == 1
        assert sorted(replayed for _, replayed in results) == [False, True]
        with database.session() as session:
            assert session.scalar(select(func.count()).select_from(WorkflowRunRecord)) == 1
            assert session.scalar(select(func.count()).select_from(CollectionReceiptRecord)) == 1
            assert session.scalar(select(func.count()).select_from(EventRecord)) == 1
            assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
            assert session.scalar(select(func.count()).select_from(AuditEntryRecord)) == 4
            assert AuditLedger().verify(
                session,
                tenant_id=UUID(tenant_id),
                case_id=hypothesis.case_id,
            )
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
