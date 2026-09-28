import json
from uuid import uuid4

from causalforge.graph.projector import TemporalAttackGraph
from causalforge.ingestion.normalizer import normalize_event


def test_graph_snapshot_is_json_serializable() -> None:
    event = normalize_event(
        {
            "event_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "source": {"kind": "fixture", "name": "test", "version": "1.0"},
            "observed_at": "2026-09-28T10:03:00Z",
            "actor": {"kind": "service_account", "id": "reader"},
            "action": "list",
            "object": {"kind": "secret", "namespace": "orders", "name": None},
            "outcome": "allowed",
            "attributes": {},
            "coverage": {
                "source_complete_for_window": True,
                "window_start": "2026-09-28T10:00:00Z",
                "window_end": "2026-09-28T10:05:00Z",
            },
        },
        parser_version="fixture-1.0",
    ).event
    graph = TemporalAttackGraph()
    graph.project_event(event, evidence_id=uuid4())

    json.dumps(graph.as_dict())
