from pathlib import Path
from uuid import uuid4

from sqlalchemy import select

from causalforge.detection.sigma_engine import load_rules
from causalforge.security.engine import DeterministicCaseEngine
from causalforge.storage.db import Database
from causalforge.storage.models import AuditEntryRecord, ClaimRecord, DetectionRecord

ROOT = Path(__file__).parents[3]


def event_payload(
    tenant_id: str, *, event_id: str, action: str, object_kind: str
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "source": {"kind": "kubernetes_audit", "name": "fixture", "version": "1.0"},
        "observed_at": "2026-09-28T10:03:00Z",
        "actor": {"kind": "service_account", "id": "system:serviceaccount:orders:reader"},
        "action": action,
        "object": {"kind": object_kind, "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {"workload_id": "orders-api"},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-28T10:00:00Z",
            "window_end": "2026-09-28T10:05:00Z",
        },
    }


def test_rule_only_engine_creates_detection_graph_and_observed_claim(tmp_path) -> None:
    tenant_id = uuid4()
    case_id = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'engine.db'}")
    database.create_schema()
    engine = DeterministicCaseEngine(
        rules=load_rules(ROOT / "rules" / "sigma"),
    )
    payloads = [
        event_payload(
            str(tenant_id),
            event_id=str(uuid4()),
            action="list",
            object_kind="secret",
        ),
        event_payload(
            str(tenant_id),
            event_id=str(uuid4()),
            action="connect",
            object_kind="service",
        ),
    ]

    with database.session() as session:
        result = engine.process(
            session,
            tenant_id=tenant_id,
            case_id=case_id,
            payloads=payloads,
            parser_version="fixture-1.0",
            title="Compromised orders workload",
        )
        session.commit()

        assert result.incident.id == str(case_id)
        assert result.incident.status == "NEW"
        assert len(result.ingested) == 2
        assert len(result.detections) == 1
        assert result.detections[0].level == "high"
        assert len(result.claims) == 1
        assert result.claims[0].status == "observed"
        assert result.claims[0].predicate == "list secret"
        assert result.claims[0].supporting_evidence_ids
        assert result.graph.neighbors(
            "workload:orders-api", relationship="uses_identity"
        ) == ["service_account:system:serviceaccount:orders:reader"]
        assert engine.audit.verify(session, tenant_id=tenant_id, case_id=case_id) is True

        assert len(list(session.scalars(select(DetectionRecord)))) == 1
        assert len(list(session.scalars(select(ClaimRecord)))) == 1
        assert len(list(session.scalars(select(AuditEntryRecord)))) == 4


def test_engine_is_idempotent_for_replayed_batch(tmp_path) -> None:
    tenant_id = uuid4()
    case_id = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'replay.db'}")
    database.create_schema()
    engine = DeterministicCaseEngine(rules=load_rules(ROOT / "rules" / "sigma"))
    payloads = [
        event_payload(
            str(tenant_id),
            event_id=str(uuid4()),
            action="list",
            object_kind="secret",
        )
    ]

    with database.session() as session:
        first = engine.process(
            session,
            tenant_id=tenant_id,
            case_id=case_id,
            payloads=payloads,
            parser_version="fixture-1.0",
        )
        session.commit()
        second = engine.process(
            session,
            tenant_id=tenant_id,
            case_id=case_id,
            payloads=payloads,
            parser_version="fixture-1.0",
        )
        session.commit()

        assert first.ingested[0].duplicate is False
        assert second.ingested[0].duplicate is True
        assert len(list(session.scalars(select(DetectionRecord)))) == 1
        assert len(list(session.scalars(select(ClaimRecord)))) == 1
        assert len(list(session.scalars(select(AuditEntryRecord)))) == 3
